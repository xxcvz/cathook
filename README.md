# Lighthook
[![C++](https://img.shields.io/badge/language-C%2B%2B-%23f34b7d.svg?style=flat-square)](https://en.wikipedia.org/wiki/C%2B%2B)
[![TF2](https://img.shields.io/badge/game-TF2-orange.svg?style=flat-square)](https://store.steampowered.com/app/440/Team_Fortress_2/)
[![GNU/Linux](https://img.shields.io/badge/platform-GNU%2FLinux-ff69b4?style=flat-square)](https://www.gnu.org/gnu/linux-and-gnu.en.html)
[![x86](https://img.shields.io/badge/arch-x86-red.svg?style=flat-square)](https://en.wikipedia.org/wiki/X86)
[![License](https://img.shields.io/github/license/explowz/cathook.svg?style=flat-square)](LICENSE)
[![Issues](https://img.shields.io/github/issues/explowz/cathook.svg?style=flat-square)](https://github.com/explowz/cathook/issues)

Free open-source GNU/Linux training software for the game **Team Fortress 2**. Designed as an internal cheat - [Shared Library](https://en.wikipedia.org/wiki/Library_(computing)#Shared_libraries) (SO) loadable into game process. Compatible with the Steam version of the game.

## Table of Contents

- [Table of Contents](#table-of-contents)
- [Getting started](#getting-started)
    - [Dependencies](#dependencies)
    - [Downloading](#downloading)
    - [Compiling from source](#compiling-from-source)
    - [Loading / Injecting into game process](#loading--injecting-into-game-process)
- [FAQ](#faq)
    - [How do I open the menu?](#how-do-i-open-the-menu)
    - [Where is my config file saved?](#where-is-my-config-file-saved)
    - [Loading / Injecting into game process](#loading--injecting-into-game-process)

## Getting started

### Dependencies

The `dialog` package is not mandatory, yet recommended.

Dependencies are handled automatically by the [dependencycheck](https://github.com/explowz/cathook/blob/master/scripts/dependencycheck) script.

### Downloading

Open a terminal window and enter the following command:

    bash <(wget -qO- https://raw.githubusercontent.com/explowz/One-in-all-cathook-install/master/install-all)

The `cathook` folder should have been created successfully, containing all source files.

### Compiling from source

When you have obtained a copy of the source code, the next step is opening it with your IDE of choice.

Then change all `-march=native -mtune=native` arguments inside [CMakeLists.txt](https://github.com/explowz/cathook/blob/master/CMakeLists.txt) to `-march=<your cpu-type> -mtune=<your cpu-type>`. This should result in more performant code, optimized for your CPU. The list of valid options can be found [here](https://gcc.gnu.org/onlinedocs/gcc/x86-Options.html).

And simply run the following command while inside the source folder:

    ./update

If everything went right you should receive a binary file named `libcathook.so`.

### Loading / Injecting into game process

Run the following command while inside the source folder:

    sudo ./attach

This will inject `libcathook.so` into the `hl2_linux` process.

When injected, the menu can be opened using the `INSERT` key.

## FAQ

### How do I open the menu?
Press <kbd>INSERT</kbd> while focused on the TF2 window.

### Where is my config file saved?
Configuration files are saved inside the `cathook` folder located in your `opt` folder (`/opt/cathook/data`). The config is in human-readable format and can be edited via your text editor of choice.
