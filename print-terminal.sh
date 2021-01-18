#!/bin/sh

if CHOICE=$(/home/apoelstra/code/filterscreen/target/release/screenfilter | rofi -dmenu -p "copy " -theme-str '#window { width: 800px; }'); then
    if [ "$CHOICE" != "" ]; then
        echo -n $CHOICE | cut -d ':' -f 2- | cut -d ' ' -f 2- | xsel
    fi
fi

