# FO2Quacks
Miscellaneous Fallout 2 hacks 

## OllyDbg function labels

Get ODbgScript plugin .dll from http://odbgscript.sf.net and put it in OllyDbg folder
Run fo2_symbols_script.txt from Plugins-menu (fo2_symbols_script.txt can be generated by running fo2re2odbgscript.py with [Fallout2-re code](https://github.com/alexbatalov/fallout2-re))

Get function names as labels and comments:

![image](https://github.com/user-attachments/assets/da357646-f6f4-4e03-bfe1-3b1f30508206)

No need to do it twice, the labels and comments are saved for the exe as .udd in the OllyDbg folder

## Skip main menu and character selection

Use the patcher to skip main menu ("autoclick" New Game) and character selection (take the first premade) to quickly boot to the default starting map. Intro movies can be disabled in the ddraw.ini

## Change the age limit to 99

In character creation screen you can only choose age up to 35. No more ageism!

<img width="284" height="74" alt="image" src="https://github.com/user-attachments/assets/cdf5a2ef-3559-4c0d-8084-15a20d83fc5c" />

## Note

<img width="609" height="536" alt="image" src="https://github.com/user-attachments/assets/e4dcc440-71a0-42c3-b7b5-b419efdcc07b" />

Remember to "Save as". Add the new CRC to ddraw.ini if using sfall.
