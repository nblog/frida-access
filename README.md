
## frida-access
let frida break through the protection (Windows), like [access](https://github.com/btbd/access)

## Usage
1. run frida-server [bit == target bit](https://github.com/frida/frida-core/blob/64361063d4319fb54bcf329d79d4e618eeab45c1/src/windows/frida-helper-process.vala#L62)
2. inject `frida-access.dll` to `frida-server.exe`
3. done