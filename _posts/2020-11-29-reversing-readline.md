---
title: Reversing RedLine Stealer
author: z0rs
date: 2020-11-29 00:00:00 +0800
---

### Key Points
- *Redline Stealer* has the ability to communicate with multiple C2 hosts.
- *Redline Stealer* has the ability to present a message box to the user upon execution.
- *Redline Stealer* communicates with the C2 server using Simple Object Access Protocol (SOAP).
- *Redline Stealer* exits if it detects the infected machine is from a near Russian countries.
- *Redline Stealer* executes its modules in random order to potentially evade heuritic detection.

## Infection Chain
Data Contract
The infection chain starts with a download of `[BigTitsRoundAsses] 17.12.14 - Jazmyn [1080p].scr` from `pornleech[.]ch`, which creates three files in the `TEMP%` directory, `Che.mp3` (Autoit Interpreter), `Quella.mp3`, (BAT Script) and `Travolge.mp3` (AutoIT Script).

## Obfuscated BAT Script

Once extracted, the installer executes `cmd /c cmd < Quella.mp3 & ping -n 5 localhost`, which later creates `Mantenga.exe.pif`, which is an AutoIT interpreter.

PLACEHOLDER (FIGURE FOR DEOBFUSCATED THE BAT SCRIPT)

### Obfuscated AutoIT Script

Next, the AutoIT interpreter executes `i`.  Then the AutoIT script performs process hollowing, creates the process `jsc.exe` in suspended mode, hollows the process then injects the process with Redline Stealer.

PLACEHOLDER (ADD FIGURE FOR AU3 DEOBFUSCATOR)

Installer → Quella.mp3 (BAT) → Mantenga.exe.pif (Loader) → jsc.exe

Looks like they are doing process hollowing from the AutoIT script.

```text
CreateProcessW
NtWriteVirtualMemory
NtReadVirtualMemory
NtWriteVirtualMemory
NtProtectVirtualMemory
NtSetContextThread
NtResumeThread
NtUnmapViewOfSection
```

## Redline Stealer

[Redline Stealer](https://malpedia.caad.fkie.fraunhofer.de/details/win.redline_stealer) is an information stealing malware available for purchase on underground forums and sells standalone and as a subscription service. This section of the blog is a technical analysis of Redline Stealer and its capabilities.

### Language Check

Once executed, *Redline Stealer* checks the country of origin against Armenia, Azerbaijan, Belarus, Kazakhstan, Kyrgyzstan, Moldova, Tajikistan, Uzbekistan, Ukraine, and Russia. Next, if `TimeZoneInfo.Local.Id` contains any of the hard-coded disallowed countries or `CultureInfo.CurrentUICulture.EnglishName` is `null` the program calls `Environment.Exit`.

## String Decryption

To decrypt strings, *Redline Stealer* calls `StrinDecrypt.Read`, which base64-decodes the ciphertext, then performs a rotating XOR operation using the key user string (`#US`) `Kenners`.

```python
import base64

class StringDecrypt():
    @staticmethod
	def Read(ciphertext: str, key: str) -> str:
	    key = key.encode()
	    ciphertext = base64.b64decode(ciphertext)
	    plaintext = []
	    for i in range(0, len(ciphertext)):
	        plaintext.append(ciphertext[i] ^ key[i % len(key)])
	    plaintext = bytes(plaintext).decode('utf-8')
	    return base64.b64decode(plaintext).decode('utf-8')
```
*Figure 1. Redline Stealer String Decryption Routine in Python*

## User Message

If the field `Arguments.Message` is not an empty or a `null` string, it is decrypted by calling `StringDecrypt.Read` (Figure 1) and subsequently presented to the user in a message box. The execution of *Redline Stealer* is not halted during this process, as the message box is created using a new thread. This functionality in Redline Stealer allows operators to present messages to users, such as fake error messages and more.

### C2 Communication

*Redline Stealer* uses SOAP messaging protocol to communicate with the C2 server. This section is a technical analysis of how *Redline Stealer* communicates with its C2 server.

#### Establish Connection

To establish a connection with the C2 server, Redline Stealer creates a new class object of `ConnectionProvider`, which handles all C2 communication. Once created, *Redline Stealer* decrypts all C2 servers from `Arguments.IP` with `StringDecrypt.Read` (Figure 1). Next, *Redline Stealer* splits the result using the delimiter `|` to create an array of C2 hosts. Once *Redline Stealer* has decrypted its array of C2 hosts, *Redline Stealer* connects to `net.tcp://95.217.35[.]153:9678/` using SOAP protocol, the default for Windows Communication Foundation (WCF). Once the WCF `ChannelFactory` object is created, *Redline Stealer* sets the field `connector` as this object. Next, *Redline Stealer* sets the SOAP header name as `Authorization`, with the namespace `ns1`. If unable to connect to the first C2 address, in a loop, *Redline Stealer* sleeps by calling `Thread.Sleep` for 5 seconds before attempting the next C2 address in the C2 hosts array. This means Redline Stealer can contain multiple C2 address, increasing the probability one of the C2 address will be operational.

#### Get Settings

*Redline Stealer* creates the data contract class `SettingsStruct`, which contains data members. These data members are the settings *Redline Stealer* uses during its execution, which are obtained from the C2 server (Table 1).

| Type                      | Name                 | Description                           |
| ------------------------- | -------------------- | ------------------------------------- |
| bool                      | Browsers             | Enable Stealing Browser Data          | 
| bool                      | FileSearch           | Enable File Stealing Module           |
| bool                      | Filezilla            | Enable Filezilla Module               |
| bool                      | Wallets              | Enable Wallet Stealing Module         |
| bool                      | GetImageBase         | Enable Collection of Image Base       |
| bool                      | ScanFiles            | Enable Scanning Files                 |
| bool                      | VPN                  | Enable Stealing VPN Credentials       |
| bool                      | StealSteam           | Enable Stealing Steam Creds           |
| bool                      | Discord              | Enable Discord Stealing Tokens        |
| List\<string\>            | FileSearchPatterns   | Patterns to Search for Files to Steal |
| List\<string\>            | ChromiumBrowserPaths | Paths for Chromium Browsers           |
| List\<string\>            | MozillaBrowserPaths  | Paths for Mozilla Browsers            |
| List\<WalletFileConfigs\> | AdditionalWallets    | Additional Wallets to Steal           |

*Table 1. Redline Stealer Settings Data Contract Members*

#### Result Data Contract

*Redline Stealer* stores results of data collected from the victim machine in a data contract, which is created with the data member `ID`. The value of this data member is `100822` originating from `Arguments.ID`, which is decrypted using `StringDecrypt.Read` and `ID` serves as the build ID.

![build_id](images/b8160dbd643f3717cd2ffc345e2a47e6ce072cc5898afb548dc50468fcafa4ff.png)
*Figure placeholder. Redline Stealer Build ID ([reference](https://www.esentire.com/blog/esentire-threat-intelligence-malware-analysis-redline-stealer))*

### Modules

*Redline Stealer* creates the class `EntityResolver`, which is created from the template method `ItemBase.Extract`. If `Arguments.Version` is not equal to `1`, an instance of `FullInfoSender` is returned, otherwise an instance of `PartsSender` is returned. In this case, `Arguments.Version` is set `1`, which returns an instance of `PartsSender`. 

Next, in a while loop, *Redline Stealer* executes the `Invoker` method from the `PartsSender` instance. Once executed, Redline Stealer initializes the data contract `SystemInfo`, which will later be populated with data stolen from the infected machine. Next, if the directory `%AppData%\Yandex\YaAddon` does not exist, Redline Stealer creates the directory. Otherwise, if the directory creation time is less than three months old, the directory is deleted and created again. Once completed, *Redline Stealer* executes modules in the module groups `First` and `Main` in random order (Table 2).

| Module Group | Module Name          | Description                         |
| ------------ | -------------------- | ----------------------------------- |
| First        | GetUsername          | Gets Username                       |
| First        | GetMonitorProperites | Gets Monitor Properties             |
| First        | GetOS                | Gets OS Name                        |
| First        | GetAssemblyLocation  | Obtains Executing Assembly Location |
| First        | GetUUID              | Created a UUID                      |
| First        | GetTimezone          | Gets Timezone                       |
| Main         | GetHardwareInfo      | Get Hardware Information            |
| Main         | GetBrowsers          | Steal Browser Data                  |
| Main         | GetListOfPrograms    | Get List of Programs                |
| Main         | GetAVs               | Get List of Security Products       |
| Main         | GetProcesses         | Get List of Processes               |
| Main         | GetLanguages         | Get Languages                       |
| Main         | GetTelegramProfiles  | Enumerate Telegram Profiles         | 
| Main         | MaybeMozillaStealer  | Maybe Steal Data From Mozilla       |
| Main         | GetFileSearch        | Get File Search Results             |
| Main         | StealWallets         | Steal Crypto Wallets                |
| Main         | StealDiscord         | Steal Discord Tokens                |
| Main         | GetGameLaunchers     | Steal Game Launcher Data            |
| Main         | GetVPN               | Steal VPN Credentials               |
| Main         | GetImageBase         | Get Executing Assembly Image Base   |

*Table 2. Redline Stealer Module Groups*

The modules in the group `First` only collect data, which is later sent to the C2 server, whereas the modules in the group `Main` send data within each module. This could mean the modules in the `First` group are working on being ported to the `Main` group.

#### GetAVs (defenders)

This module performs the WMI queries provided in Figure 2, against `ROOT\\SecurityCenter` and `ROOT\\SecurityCenter2`.

```text
SELECT * FROM AntivirusProduct
SELECT * FROM AntiSpyWareProduct
SELECT * FROM FirewallProduct
```
*Figure 2. Redline Stealer WMI Queries*

Once completed, the results are appended to a list, which is sent to the C2 server.

#### GetHardwareInfo (hardwares)

This module performs the WMI query `SELECT * FROM Win32_Processor`, collecting the `Name` and `NumberOfCores` of the infected endpoint. Additionally, another WMI query is performed on `root\\CIMV2`, with the query `SELECT * FROM Win32_VideoController`, collecting the `AdaperRAM` and `Name`. The results from both of these queries are stored in a template list. Once completed, Redline Stealer appends another structure with the hard-coded key as `Total of RAM` with the value `4095.46 MB or 4294397952`. Next, the data is sent to the C2 server.

#### ListOfPrograms (softwares)

This module opens the sub registry key `HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall`. Next, the sub key names are iterated for their `DisplayName` and associated `DisplayVersion`. Once these values are obtained, they are added to a list of strings in the format described in Figure 3.

```text
DisplayName0 [DisplayVersion0]
DisplayName1 [Displayversion1]
DisplayName3 [Displayversion3]
...
```
Figure 3. Redline Stealer Program List Module Structure

Next, the results are sent to the C2 server.

#### GetBrowsers

If the infected endpoint is 32-bit Redline Stealer opens the registry key `SOFTWARE\\Clients\\StartMenuInternet`, otherwise it reads `SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet`. Once opened, Redline Stealer iterates the sub key names, collecting the `BrowserName` and the `FileVersion` from `shell\\open\\command` (default file association). If the `FileVersion` cannot be obtained, Redline Stealer sets `BrowserVersion` to `Unknown Version`. Next, the resulting data contract structure is appended to the list template and sent to the C2 server.

#### ListProcesses (processes)

Redline Stealer performs the WMI query `SELECT * FROM Win32_Processes Where SessionId='<current-processes-session-id>'`. Once completed, the results are parsed for `ProcessId`, `Name`, and `CommandLine`. The structure of the data collected is provided in Figure 4.

```text
ID: <ProcessId>, Name: <Name>, CommandLine: <CommandLine>
```
*Figure 4. Redline Stealer Process List Structure*

#### Languages

To collect languages, *Redline Stealer* iterates `InputLanguages.InstalledInputLanguages`, appending the language `EnglishName` to a list of strings. Once the results have been collected, they are sent to the C2 server.

```csharp
public static void GetLanguages(ConnectionProvider connection, SettingsStruct settings, ref ResultStruct result)
	{
		result.SystemInfo.Languages = SystemInfoHelper.AvailableLanguages();
	}
```

#### GetTelegramProfiles

To scan for profiles, *Redline Stealer* calls the `FileScanning.Search` method, which takes an array of scanners classes to process. In this case, the only scanner class that is passed is `TelegramScanner`. Each scanner has two methods, `Find` to locate interesting directories, and `Collect` to obtain information. 

To collect a list of Telegram profiles, *Redline Stealer* first checks if the process `Telegram.exe` is currently running, if this is the case, Redline Stealer adds the directory where `Telegram.exe` exists and the folder `\tdata`, which contains Telegram session data to a list of the type `ScannerArgsStruct`, which is a data contract consisting of the members `Count`, `Directory`, `SearchPattern`, and `Recursive` (Table 3.).

| Type   | Name          | Description             |
| ------ | ------------- | ----------------------- |
| string | Count         | Number of Items Found   | 
| string | Directory     | Directory to Search     |
| string | SearchPattern | Search Pattern String   |
| bool   | Recursive     | Recursive Search or Not |

*Table 3. Redline Stealer ScannerArgs Data Contract*

Next, if *Redline Stealer* is unable to find a currently running process of `Telegram.exe`, *Redline Stealer* will add the directory `%AppData%\Telegram Desktop\tdata\` to the list of `ScannerArgsStruct` data contracts.

*Redline Stealer* in this process considers any filenames with a length of 16 in the Telegram `\tdata` folder a potential profile.

```csharp
public static void StealTelegram(ConnectionProvider connection, SettingsStruct settings, ref ResultStruct result)
	{
		if (settings.Telegram)
		{
			List<FileStruct> list = FileScanning.Search(new Extractor[]
			{
				new TelegramScanner()
			});
			result.SystemInfo.TelegramCredentials = list;
		}
	}
```

#### StealWallets

To steal cryptocurrency wallets, Redline Stealer checks if the Wallets module is enabled. If enabled, Redline Stealer initializes the first wallet module, passing the BrowserPath configuration from the C2, and initializes the crypto wallets in Figure placeholder, by splitting them by lines and into key value pairs using the delimiter `|`. 

```text
ffnbelfdoeiohenkjibnmadjiehjhajb|YoroiWallet
ibnejdfjmmkpcnlpebklmnkoeoihofec|Tronlink
jbdaocneiiinmjbjlgalhcelgbejmnid|NiftyWallet
nkbihfbeogaeaoehlefnkodbefgpgknn|Metamask
afbcbjpbpfadlkmhmclhkeeodmamcflc|MathWallet
hnfanknocfeofbddgcijnmhnfnkdnaad|Coinbase
fhbohimaelbohpjbbldcngcnapndodjp|BinanceChain
odbfpeeihdkbihmopkbjmoonfanlbfcl|BraveWallet
hpglfhgfnhbgpjdenjgmdgoeiappafln|GuardaWallet
blnieiiffboillknjnepogjhkgnoapac|EqualWallet
cjelfplplebdjjenllpjcblmjkfcffne|JaxxxLiberty
fihkakfobkmkjojpchpfgcmhfjnmnfpi|BitAppWallet
kncchdigobghenbbaddojjnnaogfppfj|iWallet
amkmjjmmflddogmhpjloimipbofnfjih|Wombat
fhilaheimglignddkjgofkcbgekhenbh|AtomicWallet
nlbmnnijcnlegkjjpcfjclmcfggfefdm|MewCx
nanjmdknhkinifnkgdcggcfnhdaammmj|GuildWallet
nkddgncdjgjfcddamfgcmfnlhccnimig|SaturnWallet
fnjhmkhhmkbjkkabndcnnogagogbneec|RoninWallet
aiifbnbfobpmeekipheeijimdpnlpgpp|TerraStation
fnnegphlobjdpkhecapkijjdkgcjhkib|HarmonyWallet
aeachknmefphepccionboohckonoeemg|Coin98Wallet
cgeeodpfagjceefieflmdfphplkenlfk|TonCrystal
pdadjkfkgcafgbceimcpbkalnfnepbnk|KardiaChain
bfnaelmomeimhlpmgjnjophhpkkoljpa|Phantom
fhilaheimglignddkjgofkcbgekhenbh|Oxygen
mgffkfbidihjpoaomajlbgchddlicgpn|PaliWallet
aodkkagnadcbobfpggfnjeongemjbjca|BoltX
kpfopkelmapcoipemfendmdcghnegimn|LiqualityWallet
hmeobnfnfcmdkdcmlblgagmfpfboieaf|XdefiWallet
lpfcbjknijpeeillifnkikgncikgfhdo|NamiWallet
dngmlblcodfobpdpecaadgfbcggfjfnm|MaiarDeFiWallet
ffnbelfdoeiohenkjibnmadjiehjhajb|YoroiWallet
ibnejdfjmmkpcnlpebklmnkoeoihofec|Tronlink
jbdaocneiiinmjbjlgalhcelgbejmnid|NiftyWallet
nkbihfbeogaeaoehlefnkodbefgpgknn|Metamask
afbcbjpbpfadlkmhmclhkeeodmamcflc|MathWallet
hnfanknocfeofbddgcijnmhnfnkdnaad|Coinbase
fhbohimaelbohpjbbldcngcnapndodjp|BinanceChain
odbfpeeihdkbihmopkbjmoonfanlbfcl|BraveWallet
hpglfhgfnhbgpjdenjgmdgoeiappafln|GuardaWallet
blnieiiffboillknjnepogjhkgnoapac|EqualWallet
cjelfplplebdjjenllpjcblmjkfcffne|JaxxxLiberty
fihkakfobkmkjojpchpfgcmhfjnmnfpi|BitAppWallet
kncchdigobghenbbaddojjnnaogfppfj|iWallet
amkmjjmmflddogmhpjloimipbofnfjih|Wombat
fhilaheimglignddkjgofkcbgekhenbh|AtomicWallet
nlbmnnijcnlegkjjpcfjclmcfggfefdm|MewCx
nanjmdknhkinifnkgdcggcfnhdaammmj|GuildWallet
nkddgncdjgjfcddamfgcmfnlhccnimig|SaturnWallet
fnjhmkhhmkbjkkabndcnnogagogbneec|RoninWallet
aiifbnbfobpmeekipheeijimdpnlpgpp|TerraStation
fnnegphlobjdpkhecapkijjdkgcjhkib|HarmonyWallet
aeachknmefphepccionboohckonoeemg|Coin98Wallet
cgeeodpfagjceefieflmdfphplkenlfk|TonCrystal
pdadjkfkgcafgbceimcpbkalnfnepbnk|KardiaChain
bfnaelmomeimhlpmgjnjophhpkkoljpa|Phantom
fhilaheimglignddkjgofkcbgekhenbh|Oxygen
mgffkfbidihjpoaomajlbgchddlicgpn|PaliWallet
aodkkagnadcbobfpggfnjeongemjbjca|BoltX
kpfopkelmapcoipemfendmdcghnegimn|LiqualityWallet
hmeobnfnfcmdkdcmlblgagmfpfboieaf|XdefiWallet
lpfcbjknijpeeillifnkikgncikgfhdo|NamiWallet
dngmlblcodfobpdpecaadgfbcggfjfnm|MaiarDeFiWallet
bhghoamapcdpbohphigoooaddinpkbai|Authenticator
ookjlbkiijinhpmnjffcofjonbfbgaoc|TempleWallet
```
*Figure placeholder. Redline Stealer Wallets*

The key is the path expected to match the wallet, and the value is the wallet name. Next, *Redline Stealer* iterates over the browser paths searching for Login Data, Web Data and Cookies. For each of the file paths matching these strings, Redline Stealer collects the valid paths for the crypto currency wallets (Figure placeholder).

```text
<browser-name>_<user-data-path>_<crypto_wallet>
"%Path%/Local Extension Settings/afbcbjpbpfadlkmhmclhkeeodmamcflc"
```

Next, Redline Stealer searches for the files wallet.dat and wallet. These results are returned in a list of scanner results.

Once completed, *Redline Stealer* collects the files identified and sends them to the C2 server.

```csharp
public static void StealWallets(ConnectionProvider connection, SettingsStruct settings, ref ResultStruct result)
	{
		if (settings.Wallets)
		{
			SearchCryptoWallets searchCryptoWallets = new SearchCryptoWallets();
			searchCryptoWallets.Init(settings.ChromiumBrowserPaths);
			List<FileStruct> list = FileScanning.Search(new Extractor[]
			{
				new WalletDats(),
				searchCryptoWallets
			});
			list.AddRange(ConfigReader.Read(settings.AdditionalWallets));
			result.SystemInfo.WalletResults = list;
		}
	}
```

#### StealDiscord

To steal Discord tokens, Redline Stealer checks if the Discord module is enabled. If the module is enabled, Redline Stealer checks the directory `%AppData%\\discord\\Local Storage\\leveldb` for the file extensions `.log` and `.ldb.` The files collected with these extensions are searched with the regex ``[A-Za-z\\d]{24}\\.[\\w-]{6}\\.[\\w-]{27}``. If a match is found, Redline Stealer adds the Discord token to a structure containing the tokens. Once completed, they are added to the SystemInfo structure, which is later sent to the C2 server.

```csharp
public static void StealDiscord(ConnectionProvider connection, SettingsStruct settings, ref ResultStruct result)
	{
		if (settings.Discord)
		{
			SystemInfo id = result.SystemInfo;
			IEnumerable<FileStruct> tokens = Discord.GetTokens();
			id.DiscordTokens = ((tokens != null) ? tokens.ToList<FileStruct>() : null);
		}
	}
```

## StealSteam

To steal Steam credentials, *Redline Stealer* checks if the `StealSteam` module is enabled. If enabled, *Redline Stealer* checks if the registry key `HKCU:\Software\Valve\Steam` if the value `SteamPath` is a directory. If the directory exists, *Redline Stealer* collects files matching the search pattern `*ssfn*` and `*.vdf`. The `ssfn` (Steam Sentry Files) are used by Steam for authentication sessions and the `.vdf` files are used to contain various types of game metadata. These files are later exfiltrated to the C2 server.

```csharp
public static void StealSteam(ConnectionProvider connection, SettingsStruct settings, ref ResultStruct result)
	{
		if (settings.StealSteam)
		{
			result.SystemInfo.StealSteam = FileScanning.Search(new Extractor[]
			{
				new Steam()
			});
		}
	}
```

#### StealVPN

To steal Nord VPN credentials, *Redline Stealer* searches the directory `%USERPROFILE%\AppData\Local\NordVPN` with the search pattern `NordVPN.exe*`. If *Redline Stealer* is able to identify a file named user.config, *Redline Stealer* extracts the username and password. 

```csharp
	public static void StealSteam(ConnectionProvider connection, SettingsStruct settings, ref ResultStruct result)
	{
		if (settings.StealSteam)
		{
			result.SystemInfo.StealSteam = FileScanning.Search(new Extractor[]
			{
				new Steam()
			});
		}
	}

```

To steal OpenVPN credentials, *Redline Stealer* collects files the directory `%USERPROFILE%\\AppData\\Roaming\\OpenVPN Connect\\profiles` using the search pattern `*ovpn`.

To steal ProtonVPN credentials, *Redline Stealer* collects files the directory `%USERPROFILE%\\AppData\\Local\ProtonVPN` using the search pattern `*ovpn`.

```csharp
public static void StealVPN(ConnectionProvider connection, SettingsStruct settings, ref ResultStruct result)
	{
		if (settings.VPN)
		{
			result.SystemInfo.NordVPN = NordApp.Find();
			result.SystemInfo.OpenVPN = FileScanning.Search(new Extractor[]
			{
				new OpenVPN()
			});
			result.SystemInfo.ProtonVPN = FileScanning.Search(new Extractor[]
			{
				new ProtonVPN()
			});
		}
	}
```

#### StealBrowsers

To steal browser credentials, Redline Stealer iterates over browser paths provided for both Chromium and Mozilla based browsers from the the configuration. To steal the data, *Redline Stealer* iterates over the directories `Login Data`, `Web Data`, `Cookies` and `Extension Cookies`. During this process *Redline Stealer* collects cookies, the browser name, the path to the `User Data` directory, saved passwords, autofill data, and credit cards. Most of the data collected from the browsers is from the sqlite database and is easily decrypted.

```csharp
public static void BrowserStealer(ConnectionProvider connection, SettingsStruct settings, ref ResultStruct result)
	{
		if (settings.Browsers)
		{
			List<BrowserCredentials> list = new List<BrowserCredentials>();
			list.AddRange(Chromium.Steal(settings.ChromiumBrowserPaths));
			list.AddRange(Mozilla.Steal(settings.MozillaBrowserPaths));
			result.SystemInfo.BrowserCredentials = list;
		}
	}
```

#### Remote Tasks

To execute remote tasks, Redline Stealer makes a request to the C2 server. Next, Redline Stealer is able to perform four types of remote tasks. These remote tasks include arbitrary command execution, downloading of files, downloading and execution of files and executing files (Table placeholder).

| Task                        | Example                                                 | Description                             |
| --------------------------- | ------------------------------------------------------- | --------------------------------------- |
| Arbitrary Command Execution | `whoami`                                                  | Execute Command using `cmd /C <command` |
| Download File               | `http://example.com/example.exe\|%AppData%\\example.exe` | Download a File                         |
| Download and Execute        | `http://example.com/example.exe\|%AppData%\\example.exe` | Download and Execute a File             |
| Execute a File              | `C:\Users\example\example.exe`                          | Execute a File                          | 

*Table placeholder. Redline Stealer Remote Tasks*

## Configuration Extraction

I have created a configuration extractor, which is available [here](https://github.com/c3rb3ru5d3d53c/mwcfg-modules/blob/f1064aea63d11b5069a1839cf2b9d10d43cee1aa/redline/redline.py).

```bash
mwcfg -m modules/ -i tests/redline/676ae4b1ef05ee0ec754a970cce61a5f8d3093989a58c33087a3a5dca06364aa --pretty | jq
[
  {
    "name": "tests/redline/676ae4b1ef05ee0ec754a970cce61a5f8d3093989a58c33087a3a5dca06364aa",
    "type": "PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows",
    "mime": "application/x-dosexec",
    "md5": "396c2688c0469b0cb0d83167d27eca31",
    "sha1": "a1f91b8b153d017593119984fbce936c5113a137",
    "sha256": "676ae4b1ef05ee0ec754a970cce61a5f8d3093989a58c33087a3a5dca06364aa",
    "configs": [
      {
        "hosts": [
          "95.217.35.153:9678"
        ],
        "id": "100822",
        "family": "redline"
      }
    ]
  }
]
```
*Figure placeholder. Redline Stealer Configuration Extraction*

## Downloads

- [Source Code](samples/2023-02-18-redline-src.zip)
- [Samples](samples/2023-02-18-redline-samples.zip)

## Indicators of Compromise

| Type   | Indicator                                                        | Description                    |
| ------ | ---------------------------------------------------------------- | ------------------------------ |
| SHA256 | 532c47de5bdd433bea776290d27a741b09a1d5c5f2089e54eced922514a60799 | Redline Stealer Installer File |
| SHA256 | 3e8d604a5d545189c35d810845b3e2208e3c56081507b949ecb17a6bbd4decb1 | Messed Up PE File (Che.mp3)    |
| SHA256 | ac5f7f01c7ca6663810df33bfa62012368b6c17b7520943c094308f30adac766 | BAT Script (Quella.mp3)        |
| SHA256 | 454b381e98f092cab4e82f21a790c5ccd4dbd006e44925bcabd6c9289ea6700e | AutoIT Script  (Travolge.mp3)  |
| SHA256 | 3e26723394ade92f8163b5643960189cb07358b0f96529a477d37176d68aa0a0 | AutoIT Interpreter             |
| SHA256 | 454b381e98f092cab4e82f21a790c5ccd4dbd006e44925bcabd6c9289ea6700e | AutoIT Script                  |
| SHA256 | 676ae4b1ef05ee0ec754a970cce61a5f8d3093989a58c33087a3a5dca06364aa | Redline Stealer (Unpacked)     |
| IPv4   | 95.217.35[.]153                                                  | Redline Stealer C2             |
| SHA256 | 2ccf3271c2e61033cddaf0af23854fc73cdaf7eab15745c419f269b8b24687c6 | Redline Stealer Deobfuscated   | 

## Detection

This section contains signatures to detect Redline Stealer and its infection chain.

### YARA

Placeholder

### Suricata

Placeholder

## Mitre Attack TTPs

| ID          | Tactic      | Technique   |
| ----------- | ----------- | ----------- |
| placeholder | placeholder | placeholder | 
