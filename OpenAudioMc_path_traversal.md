# Vulnerability Report – OpenAudioMc “show” Module Path Traversal

## Summary

A path traversal vulnerability in OpenAudioMc allows any user with access to the `/openaudiomc show` command set to write arbitrary `.json` files outside the plugin’s data directory. Because the command accepts unsanitized show names, crafted input permits directory escape via `../`, enabling persistent tampering with other plugins or core configuration on the Minecraft server.

## Product Information

- **Product**: OpenAudioMc  
- **Component**: Spigot `show` command module  
- **Version**: Confirmed on Git commit 15efc335 (latest as of 31 Oct 2025); older versions using the same `ShowService`/`Show` code path are likely affected  
- **Environment**: Spigot/Bukkit-based Minecraft servers running the OpenAudioMc plugin

### Relevant Code Paths

1. `ShowCreateSubCommand.onExecute()` (`Plugin/src/main/java/com/craftmend/openaudiomc/spigot/modules/commands/subcommands/show/ShowCreateSubCommand.java`, lines 17–20) calls:

   ```java
   OpenAudioMc.getService(ShowService.class).createShow(args[1]);
   ```

2. `ShowService#createShow()` (`ShowService.java`, lines 57–63) writes:

   ```java
   Show show = new Show(name).save();
   showCache.put(name.toLowerCase(), show);
   ```

3. `Show.save()` (`Show.java`, lines 132–139) constructs the file path using the raw name:

   ```java
   new File(OpenAudioMcSpigot.getInstance().getDataFolder(), showName.toLowerCase() + ".json");
   BufferedWriter writer = Files.newBufferedWriter(file.toPath(), charset);
   ```

   No sanitization or canonicalization occurs; thus inputs like `../malicious/config` produce the file `plugins/malicious/config.json`.

## Proof of Concept

1. Log in as a user with `/openaudiomc` permissions.  

2. Execute:

   ```
   /openaudiomc show create ../override
   /openaudiomc show add ../override 1000 command say owned
   ```

3. Observe a new file `plugins/override.json`.

Attackers can target any writable location. For example, `/openaudiomc show create ../../WorldEdit/config` writes to `plugins/../../WorldEdit/config.json`, potentially corrupting another plugin’s settings.

## Impact

- Overwrite configuration files of other plugins or the server (e.g., permission systems, security plugins).  
- Plant crafted JSON data that triggers logic errors or further code execution in consumers.  
- Persist malicious changes across restarts because the `create` command writes directly to disk.

Because many administrative workflows include delegating OpenAudioMc commands to staff, a compromised moderator account could permanently backdoor the server.

## Mitigation

1. Normalize and validate show paths prior to writing or reading:

   ```java
   Path dataDir = OpenAudioMcSpigot.getInstance().getDataFolder().toPath();
   Path target = dataDir.resolve(showName + ".json").normalize();
   if (!target.startsWith(dataDir)) throw new IllegalArgumentException("Invalid show name");
   ```

2. Restrict show names to an allow-list (letters, numbers, `-`, `_`).  

3. Apply the same guard in `ShowService#fromFile` before opening the file.  

4. After patching, audit `plugins/` for unexpected `.json` files and restore from trusted backups.
