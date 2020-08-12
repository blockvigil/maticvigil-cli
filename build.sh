pyinstaller --onefile click_cli.py --hidden-import click --clean --name="mv-cli"
mkdir maticvigil-cli
mv dist/mv-cli maticvigil-cli/
chmod +x maticvigil-cli/mv-cli
cp README.md maticvigil-cli/
zip -r mv-cli-${TRAVIS_OS_NAME}.zip maticvigil-cli
rm -rf maticvigil-cli
mv mv-cli-${TRAVIS_OS_NAME}.zip dist/
ls dist/
