# SuperFunkyChat-Dissector

This is a Wireshark dissector for the SuperFunkyChat TCP protocol used by the [SuperFunkyChat](https://github.com/tyranid/SuperFunkyChat) application.

SuperFunkyChat is an example binary protocol application written by [James Forshaw (tyranid)](https://github.com/tyranid) and is referenced in the book **Attacking Network Protocols**.

The book only describes how to make a UDP dissector because of the higher complexity of TCP dissectors. To explain why a TCP dissector is more complex I'll just quote the [Wireshark wiki](https://wiki.wireshark.org/Lua/Dissectors#TCP_reassembly) on writing TCP dissectors:

> You should make sure your dissector can handle the following conditions:
>
> - The TCP packet segment might only have the first portion of your message.
> - The TCP packet segment might contain multiple of your messages.
> - The TCP packet might be in the middle of your message, because a previous segment was not captured. For example, if the capture started in the middle of a TCP session, then the first TCP segment will be given to your dissector function, but it may well be a second/third/etc. segment of your protocol's whole message, so appear to be malformed. Wireshark will keep trying your dissector for each subsequent segment as well, so that eventually you can find the beginning of a message format you understand.
> - The TCP packet might be cut-off, because the user set Wireshark to limit the size of the packets being captured.
  Any combination of the above.

I decided to make this to learn more about TCP dissectors. The example dissector `fpm.lua` found in the [Lua/Examples section](https://wiki.wireshark.org/Lua/Examples#A_dissector_tutorial_with_TCP-reassembly) of the wiki has been very helpful for this.

## Usage

To load this script you can use the command line flag `-X`:

```
wireshark -X lua_script:/path/to/chat-dissector.lua
```

It can also be loaded by adding it to your plugins directory. Check the [official documentation](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html) on Lua support for more information.

## Screenshot
![Screenshot of the Wireshark application capturing SuperFunkyChat packets. A response to the 'list' command is highlighted, which contains a list of connected users.](/img/dissector.png?raw=true "Dissector")
