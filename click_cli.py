import time
import webbrowser
import sys
import click
import requests
from eth_account.messages import defunct_hash_message, encode_defunct
from eth_account.account import Account
from utils.http_helper import make_http_call
from utils.exceptions import *
import json
import os
import pwd
from eth_utils import to_normalized_address
from solidity_parser import parser
from utils.EVContractUtils import extract_abi, ABIParser

CONTEXT_SETTINGS = dict(
    help_option_names=['-h', '--help']
)



CLEAN_SLATE_SETTINGS = {
    "PRIVATEKEY": None,
    "INTERNAL_API_ENDPOINT": "https://mainnet.maticvigil.com/api" if not "MATICVIGIL_API_ENDPOINT" in os.environ else os.environ['MATICVIGIL_API_ENDPOINT'],
    "REST_API_ENDPOINT": None,
    "MATICVIGIL_USER_ADDRESS": "",
    "MATICVIGIL_API_KEY": "",
    "MATICVIGIL_READ_KEY": ""
}

if "MATICVIGIL_CLI_TESTMODE" in os.environ:
    settings_json_loc = os.getcwd() + '/.maticvigil/settings.json'
    settings_json_parent_dir = os.getcwd() + '/.maticvigil'
else:
    settings_json_loc = pwd.getpwuid(os.getuid()).pw_dir + '/.maticvigil/settings.json'
    settings_json_parent_dir = pwd.getpwuid(os.getuid()).pw_dir + '/.maticvigil'


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.pass_context
def cli(ctx):
    s = CLEAN_SLATE_SETTINGS
    try:
        with open(settings_json_loc, 'r') as f:
            s = json.load(f)
    except:
        try:
            os.stat(settings_json_parent_dir)
        except:
            os.mkdir(settings_json_parent_dir)
    finally:
        ctx.obj = {'settings': s}

    if ctx.invoked_subcommand is None:
        click.secho('Run `mv-cli --help` or `mv-cli -h` for quick summary of available commands', fg='yellow')
        if s['PRIVATEKEY'] is None:
            click.secho('Run `mv-cli init` to initialize and set up a developer account', fg='yellow')
            if click.confirm(
                    click.style(
                        'Do you wish to setup and initialize a new MaticVigil developer account?',
                        fg='bright_white'
                    )
            ):
                ctx.invoke(init)


def ev_login(internal_api_endpoint, private_key, verbose=False):
    msg = "Trying to login"
    message_hash = encode_defunct(text=msg)
    signed_msg = Account.sign_message(message_hash, private_key)
    # --MATICVIGIL API CALL---
    headers = {'accept': 'application/json', 'Content-Type': 'application/json'}
    r = requests.post(internal_api_endpoint + '/login',
                      json={'msg': msg, 'sig': signed_msg.signature.hex()}, headers=headers)
    if verbose:
        click.echo(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        return r['data']
    else:
        return None


def ev_signup(internal_api_endpoint, invite_code, private_key, verbose):
    msg = "Trying to signup"
    message_hash = encode_defunct(text=msg)
    signed_msg = Account.sign_message(message_hash, private_key)
    # --MATICVIGIL API CALL to /signup---
    try:
        r = requests.post(internal_api_endpoint + '/signup', json={
            'msg': msg, 'sig': signed_msg.signature.hex(), 'code': invite_code
        })
    except:
        return False
    else:
        if verbose:
            print(r.url)
            print(r.text)
        if r.status_code == requests.codes.ok:
            return r.json()
        else:
            return False


def fill_rest_api_endpoint(new_endpoint):
    with open(settings_json_loc, 'w') as f:
        j = json.load(f)
        if 'REST_API_ENDPOINT' not in j or j['REST_API_ENDPOINT'] != new_endpoint:
            j['REST_API_ENDPOINT'] = new_endpoint
            json.dump(j, f)
            click.echo('Set REST API endpoint for contract calls in settings.json')
            click.echo(new_endpoint)


@cli.command()
@click.option('--verbose', 'verbose', default=False, type=bool)
@click.pass_obj
def init(ctx_obj, verbose):
    """
    Launches a signup process if no MaticVigil credentials are found.
    """
    if not ctx_obj['settings']['PRIVATEKEY']:
        if "MATICVIGIL_CLI_TESTMODE" not in os.environ:
            click.secho('Redirecting to the signup page...', fg='green')
            time.sleep(2)
            webbrowser.open('https://mainnet.maticvigil.com/?clisignup=true')
        invite_code = click.prompt('Enter your invite code')
        new_account = Account.create('RANDOM ENTROPY WILL SUCK YOUR SOUL')
        signup_status = ev_signup(ctx_obj['settings']['INTERNAL_API_ENDPOINT'], invite_code, new_account.key.hex(), verbose)
        if not signup_status:
            click.echo('Signup failed')
            return
        else:
            ctx_obj['settings']['PRIVATEKEY'] = new_account.key.hex()
            ctx_obj['settings']['MATICVIGIL_USER_ADDRESS'] = new_account.address

            with open(settings_json_loc, 'w') as f:
                json.dump(ctx_obj['settings'], f)
            click.echo('Sign up succeeded...')
            click.echo('Logging in with your credentials...')
            login_data = ev_login(ctx_obj['settings']['INTERNAL_API_ENDPOINT'], new_account.key.hex(), verbose)
            if len(login_data.keys()) > 0:
                ctx_obj['settings']['MATICVIGIL_API_KEY'] = login_data['key']
                ctx_obj['settings']['READ_API_KEY'] = login_data['readKey']
                ctx_obj['settings']['REST_API_ENDPOINT'] = login_data['api_prefix']

                click.echo('You have signed up and logged in successfully to MaticVigil')
                if verbose:
                    click.echo('---YOU MIGHT WANT TO COPY THESE DETAILS TO A SEPARATE FILE---')
                    click.echo('===Private key (that signs messages to interact with MaticVigil APIs===')
                    click.echo(ctx_obj['settings']['PRIVATEKEY'])
                    click.echo('===ETHEREUM hexadecimal address corresponding to above private key===')
                    click.echo(ctx_obj['settings']['MATICVIGIL_USER_ADDRESS'])
                with open(settings_json_loc, 'w') as f:
                    json.dump(ctx_obj['settings'], f)
                if verbose:
                    click.echo('Wrote context object to settings location')
                    click.echo(settings_json_loc)
                    click.echo('Context object')
                    click.echo(ctx_obj)
                sys.exit(0)
            else:
                click.echo('Login failed with credentials. Run `mv-cli reset`.')
                sys.exit(2)
    else:
        click.secho(
            "A registered private key exists for this mv-cli installation. Run mv-cli reset if you wish"
            " to do a fresh install",
            fg='yellow'
        )
        sys.exit(1)


@cli.command()
@click.pass_obj
def reset(ctx_obj):
    """
    Resets CLI and deletes existing credentials
    """
    if click.confirm(
            click.style(
                'Do you want to reset the current MaticVigil CLI configuration and state?',
                fg='bright_white'
            )
    ):
        try:
            with open(settings_json_loc, 'w') as f2:
                json.dump(CLEAN_SLATE_SETTINGS, f2)
        finally:
            click.secho(
                'MaticVigil CLI tool has been reset. Run `mv-cli init` '
                'or `mv-cli importsettings` to reconfigure.',
                fg='green'
            )


@cli.command()
@click.option('--verbose', 'verbose_flag', type=bool, default=False)
@click.pass_obj
def login(ctx_obj, verbose_flag):
    """
    Health check account and repopulate settings file
    """
    if not ctx_obj['settings']['PRIVATEKEY']:
        click.echo('No Private Key configured in settings.json to interact with MaticVigil APIs. Run `mv-cli init`.')
        return
    click.echo(ctx_obj)
    account_data = ev_login(internal_api_endpoint=ctx_obj['settings']['INTERNAL_API_ENDPOINT'],
                            private_key=ctx_obj['settings']['PRIVATEKEY'],
                            verbose=verbose_flag)
    fill_rest_api_endpoint(account_data['api_prefix'])


@cli.command()
@click.option('--raw', 'raw', type=bool, default=False)
@click.pass_obj
def accountinfo(ctx_obj, raw):
    """
    MaticVigil account information.
    Displays API keys, request end points, registered contracts against the set up account.
    """
    if not ctx_obj['settings']['PRIVATEKEY']:
        click.secho('No account set up yet. Run `mv-cli init` or `mv-cli importsettings`. Check docs for instructions.', fg='red')
        sys.exit(0)
    a_data = ev_login(internal_api_endpoint=ctx_obj['settings']['INTERNAL_API_ENDPOINT'],
                      private_key=ctx_obj['settings']['PRIVATEKEY'],
                      verbose=False)
    if not raw:
        for k in a_data:
            d = a_data[k]
            if k == 'contracts':
                click.echo(f'Contracts deployed/verified:\n=============')
                for _k in d:
                    del(_k['appId'])
                    click.echo(f'Name: {_k["name"]}')
                    click.echo(f'Address: {_k["address"]}')
                    click.echo('--------------------')
            elif k == 'key':
                click.echo(f'MaticVigil API (secret) key: \t {d}\n=============\n')
            elif k == 'readKey':
                click.echo(f'MaticVigil API (read) key: \t {d}\n=============\n')
            elif k == 'api_prefix':
                click.echo(f'REST API prefix: \t {d}\n=============\n')
            elif k == 'hooks':
                click.echo(f'Registered integrations/hooks: \t {d}\n=============\n')
            elif k == 'hook_events':
                click.echo(f'Contracts events fired to registered hooks: \t {d}\n=============\n')
    else:
        click.echo(a_data)


@cli.command()
@click.pass_obj
def dumpsettings(ctx_obj):
    """
    Prints out account settings.
    """
    click.echo(json.dumps(ctx_obj['settings']))


@cli.command()
@click.argument('importfile', type=click.File('r'))
@click.option('--verbose', 'verbose', type=bool, default=False)
def importsettings(importfile, verbose):
    """
    Import developer account from an existing settings.json
    """
    settings = json.load(importfile)
    if verbose:
        click.echo('Got settings from input file: ')
        click.echo(settings)
    # write into settings.json
    with open(pwd.getpwuid(os.getuid()).pw_dir+'/.maticvigil/settings.json', 'w') as f:
        json.dump(settings, f)


@cli.command()
@click.option('--contractName', 'contract_name',
              help='name of the contract to be deployed. For eg. ERC20Mintable. REQUIRED. '
                   'If you do not specify, you shall be prompted for the same.')
@click.option('--constructorInputs', 'inputs',
              help='constructor input values as a JSON list. OPTIONAL. If you do not specify, you shall be prompted for the same. '
                   'Eg: \'["abced", "0x008604d4997a15a77f00CA37aA9f6A376E129DC5"]\' '
                   'for constructor inputs of type (string, address). '
                   'Can be left empty if there are no inputs accepted by the constructor')
@click.option('--verbose', 'verbose', type=bool, default=False)
@click.argument('contract', type=click.Path(exists=True, dir_okay=False))
@click.pass_obj
def deploy(ctx_obj, contract_name, inputs, verbose, contract):
    """
    Deploys a smart contract from the solidity source code specified

    CONTRACT: path to the solidity file

    Usage example: mv-cli deploy contracts/Microblog.sol --contractName=Microblog --constructorInputs='JSON representation of the constructor arguments in an array'
    """
    constructor_input_prompt = False
    if contract_name:
        if verbose:
            click.echo('Got contract name: ')
            click.echo(contract_name)
    else:
        contract_name = click.prompt('Enter the contract name')
    if verbose:
        click.echo('Got constructor inputs: ')
        click.echo(inputs)
    if inputs:
        if verbose:
            click.echo('Got constructor inputs: ')
            click.echo(inputs)
        c_inputs = json.loads(inputs)
    else:
        constructor_input_prompt = True
        c_inputs = list()  # an empty list
    sources = dict()
    if contract[0] == '~':
        contract_full_path = os.path.expanduser(contract)
    else:
        contract_full_path = contract
    resident_directory = ''.join(map(lambda x: x+'/', contract_full_path.split('/')[:-1]))
    contract_file_name = contract_full_path.split('/')[-1]
    contract_file_obj = open(file=contract_full_path)

    main_contract_src = ''
    while True:
        chunk = contract_file_obj.read(1024)
        if not chunk:
            break
        main_contract_src += chunk
    sources[f'mv-cli/{contract_file_name}'] = {'content': main_contract_src}
    # loop through imports and add them to sources
    source_unit = parser.parse(main_contract_src)
    source_unit_obj = parser.objectify(source_unit)

    for each in source_unit_obj.imports:
        import_location = each['path'].replace("'", "")
        # TODO: follow specified relative paths and import such files too
        if import_location[:2] != './':
            click.echo(f'You can only import files from within the same directory as of now', err=True)
            return
        # otherwise read the file into the contents mapping
        full_path = resident_directory + import_location[2:]
        imported_contract_obj = open(full_path, 'r')
        contract_src = ''
        while True:
            chunk = imported_contract_obj.read(1024)
            if not chunk:
                break
            contract_src += chunk
        sources[f'mv-cli/{import_location[2:]}'] = {'content': contract_src}

    if len(c_inputs) == 0 and constructor_input_prompt:
        abi_json = extract_abi(ctx_obj['settings'], {'sources': sources, 'sourceFile': f'mv-cli/{contract_file_name}'})
        abp = ABIParser(abi_json=abi_json)
        abp.load_abi()
        if len(abp.constructor_params()) > 0:
            click.echo('Enter constructor inputs...')
            for idx, each_param in enumerate(abp.constructor_params()):
                param_type = abp._constructor_mapping["constructor"]["input_types"][idx]
                param_type_cat = abp.type_category(param_type)
                arg = click.prompt(f'{each_param}({param_type})')
                if param_type_cat == 'integer':
                    arg = int(arg)
                elif param_type_cat == 'array':
                    # check if it can be deserialized into a python dict
                    try:
                        arg_dict = json.loads(arg)
                    except json.JSONDecodeError:
                        click.echo(f'Parameter {each_param} of type {param_type} '
                                   f'should be correctly passed as a JSON array', err=True)
                        sys.exit(1)
                c_inputs.append(arg)
    msg = "Trying to deploy"
    message_hash = encode_defunct(text=msg)
    # deploy from alpha account
    signed_msg = Account.sign_message(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    deploy_json = {
        'msg': msg,
        'sig': signed_msg.signature.hex(),
        'name': contract_name,
        'inputs': c_inputs,
        'sources': sources,
        'sourceFile': f'mv-cli/{contract_file_name}'
    }
    # click.echo(deploy_json)
    # --MATICVIGIL API CALL---
    r = requests.post(ctx_obj['settings']['INTERNAL_API_ENDPOINT'] + '/deploy', json=deploy_json)
    if verbose:
        click.echo('MaticVigil deploy response: ')
        click.echo(r.text)
    if r.status_code == requests.codes.ok:
        click.echo(f'Contract {contract_name} deployed successfully')
        r = r.json()
        click.echo(f'Contract Address: {r["data"]["contract"]}')
        click.echo(f'Deploying tx: {r["data"]["hash"]}')
    else:
        click.echo('Contract deployment failed')


@cli.command()
@click.argument('contract', required=True)
@click.argument('url', required=True)
@click.pass_obj
def registerhook(ctx_obj, contract, url):
    """
    Registers a webhook endpoint and returns an ID for hook
    """
    headers = {'accept': 'application/json', 'Content-Type': 'application/json',
               'X-API-KEY': ctx_obj['settings']['MATICVIGIL_API_KEY']}
    msg = 'dummystring'
    message_hash = encode_defunct(text=msg)
    sig_msg = Account.sign_message(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    method_args = {
        "msg": msg,
        "sig": sig_msg.signature.hex(),
        "key": ctx_obj['settings']['MATICVIGIL_API_KEY'],
        "type": "web",
        "contract": contract,
        "web": url
    }
    r = requests.post(url=f'{ctx_obj["settings"]["INTERNAL_API_ENDPOINT"]}/hooks/add', json=method_args, headers=headers)
    click.echo(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        if not r['success']:
            click.echo('Failed to register webhook with MaticVigil API...')
        else:
            hook_id = r["data"]["id"]
            click.echo('Succeeded in registering webhook with MaticVigil API...')
            click.echo(f'MaticVigil Hook ID: {hook_id}')
    else:
        click.echo('Failed to register webhook with MaticVigil API...')


@cli.command()
@click.option('--interactive', '-i', is_flag=True, help='Turn on interactive mode')
@click.option('--verbose', '-v', is_flag=True, help='Verbose')
@click.option('--contractAddress', 'contract_address', help='Address of an already deployed contract')
@click.option(
    '--contractName',
    'contract_name',
    help='Exact string representing the name of a deployed contract'
)
@click.option(
    '--compilerVersion',
    'solidity_compiler',
    help='Exact string representing the version of the Solidity compiler that compiled the deployed contract. '
         'For eg. \'v0.5.17+commit.d19bba13\''
)
@click.option(
    '--optimization',
    'optimization',
    type=bool,
    help='Boolean: was optimization turned on during compilation'
)
@click.option(
    '--contractFile',
    'contract_file',
    help='Location of the file that contains the contract code',
    type=click.Path(exists=True, dir_okay=False)
)
@click.pass_obj
def verifycontract(ctx_obj, verbose, interactive, contract_address, contract_name, solidity_compiler, optimization, contract_file):
    """
    Verify and add a contract to your MaticVigil account that was previously deployed through a different interface, for eg. https://remix.ethereum.org
    """
    headers = {'accept': 'application/json', 'Content-Type': 'application/json',
              'X-API-KEY': ctx_obj['settings']['MATICVIGIL_API_KEY']}
    main_contract_src = ''
    if not contract_file or interactive:
        contract_address = click.prompt('Contract address to be verified')
        contract_address = to_normalized_address(contract_address)
        contract_name = click.prompt('Contract name')
        contract_file = click.prompt('Location of Solidity file', type=click.Path(exists=True, dir_okay=False))
        with open(contract_file, 'r') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                main_contract_src += chunk
        click.secho('Getting a list of compiler versions...', fg='green')
        # get list of compilers
        compilers = dict()
        try:
            c_r = make_http_call(
                request_type='get',
                url=ctx_obj['settings']['INTERNAL_API_ENDPOINT'] + '/compilers',
                headers={'accept': 'application/json'}
            )
        except Exception as e:
            click.echo('Exception retrieving list of compilers', err=True)
            if isinstance(e, EVHTTPError):
                click.echo('Possible HTTP error. Try with --verbose flag for more information', err=True)
                if verbose:
                    click.echo(e.__str__(), err=True)
            elif isinstance(e, EVAPIError):
                click.echo('Possible API error.Try with --verbose flag for more information', err=True)
                if verbose:
                    click.echo(e.__str__(), err=True)
            elif isinstance(e, EVBaseException) and verbose:
                click.echo(e.__str__(), err=True)
            sys.exit(1)
        if type(c_r['data']) == list:
            if len(c_r['data']) < 1:
                click.echo('Got empty list of compilers. Exiting...', err=True)
                sys.exit(1)
            for idx, each in enumerate(c_r['data']):
                compilers[idx] = each
            click.echo_via_pager(_gen_compilers_list(compilers))
        i = click.prompt('Select option from compiler versions above. Eg. 2', type=int)
        solidity_compiler = compilers[i-1]['full']
        optimization = click.confirm('Optimization enabled?')
    else:
        with open(contract_file, 'r') as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                main_contract_src += chunk
    msg = 'dummystring'
    message_hash = encode_defunct(text=msg)
    sig_msg = Account.sign_message(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    method_args = {
        'msg': msg,
        'sig': sig_msg.signature.hex(),
        'contractAddress': contract_address,
        'skipCompiling': False,
        'name': contract_name,
        'version': solidity_compiler,
        'optimization': optimization,
        'code': main_contract_src
    }
    click.secho(
        f'Verifying contract {contract_name} at {contract_address} from source {contract_file}...',
        fg='bright_white'
    )
    try:
        c_r = make_http_call(
            request_type='post',
            url=ctx_obj['settings']['INTERNAL_API_ENDPOINT'] + '/verify',
            headers={'accept': 'application/json'},
            params=method_args
        )
    except Exception as e:
        click.echo('Exception verifying contract', err=True)
        if isinstance(e, EVHTTPError):
            click.echo('Possible HTTP error. Try with --verbose flag for more information', err=True)
            if verbose:
                click.echo(e.__str__(), err=True)
        elif isinstance(e, EVAPIError):
            click.echo('Possible API error.Try with --verbose flag for more information', err=True)
            if verbose:
                click.echo(e.__str__(), err=True)
        elif isinstance(e, EVBaseException) and verbose:
            click.echo(e.__str__(), err=True)
        sys.exit(1)
    else:
        click.secho('Contract verified!', fg='green')


@cli.command()
@click.argument('contractaddress', required=True)
@click.argument('hookid', required=True)
@click.argument('events', required=False)
@click.pass_obj
def addhooktoevent(ctx_obj, contractaddress, hookid, events):
    """
    Receive smart contract events as JSON payloads.
    This delivers JSON payloads to the webhook endpoint registered against the HOOKID.

    HOOKID is received after calling `mv-cli registerhook`

    EVENTS is a list of events on which the hook will be registered.
    For example: ['*'] or ['Transfer', 'Approve'].
    If you do not pass this argument, all events will be pushed to the hook endpoint.
    """
    msg = 'dummystring'
    message_hash = encode_defunct(text=msg)
    sig_msg = Account.sign_message(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    events_to_be_registered_on = list()
    if not events:
        events_to_be_registered_on.append('*')
    else:
        for each in events.split(','):
            events_to_be_registered_on.append(each)
    method_args = {
        "msg": msg,
        "sig": sig_msg.signature.hex(),
        "key": ctx_obj['settings']['MATICVIGIL_API_KEY'],
        "type": "web",
        "contract": contractaddress,
        "id": hookid,
        "events": events_to_be_registered_on
    }
    headers = {'accept': 'application/json', 'Content-Type': 'application/json',
               'X-API-KEY': ctx_obj['settings']['MATICVIGIL_API_KEY']}
    click.echo(f'Registering | hook ID: {hookid} | events: {events_to_be_registered_on} | contract: {contractaddress}')
    r = requests.post(url=f'{ctx_obj["settings"]["INTERNAL_API_ENDPOINT"]}/hooks/updateEvents', json=method_args,
                      headers=headers)
    click.echo(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        if r['success']:
            click.echo('Succeeded in adding hook')
        else:
            click.echo('Failed to add hook')
            return
    else:
        click.echo('Failed to add hook')
        return


@cli.command()
@click.argument('contractaddress', required=True)
@click.argument('hookid', required=True)
@click.pass_obj
def enabletxmonitor(ctx_obj, contractaddress, hookid):
    """
    Receive transactions on contracts as JSON payloads.

    CONTRACTADDRESS is the address of a deployed and registered contract on your MaticVigil account.

    HOOKID is received after calling `mv-cli registerhook`
    """
    # enable tx monitoring on contract
    msg = 'dummystring'
    message_hash = encode_defunct(text=msg)
    sig_msg = Account.sign_message(message_hash, ctx_obj['settings']['PRIVATEKEY'])
    method_args = {
        "msg": msg,
        "sig": sig_msg.signature.hex(),
        "key": ctx_obj['settings']['MATICVIGIL_API_KEY'],
        "type": "web",
        "contract": contractaddress,
        "id": hookid,
        "action": "set"
    }
    headers = {'accept': 'application/json', 'Content-Type': 'application/json',
               'X-API-KEY': ctx_obj["settings"]["MATICVIGIL_API_KEY"]}
    r = requests.post(url=f'{ctx_obj["settings"]["INTERNAL_API_ENDPOINT"]}/hooks/transactions', json=method_args,
                      headers=headers)
    click.echo(r.text)
    if r.status_code == requests.codes.ok:
        r = r.json()
        if r['success']:
            click.echo('Succeded in adding hook to monitor all contract txs')
        else:
            click.echo('Failed to add hook to monitor on all contract txs...')
    else:
        click.echo('Failed to add hook to monitor on all contract txs...')


@cli.command()
@click.argument('contractaddress', required=True)
@click.option('--verbose', 'verbose', type=bool, default=False)
@click.pass_obj
def getoas(ctx_obj, contractaddress, verbose):
    """
    Returns OpenAPI spec link against a contract
    """
    a_data = ev_login(ctx_obj['settings']['INTERNAL_API_ENDPOINT'], ctx_obj['settings']['PRIVATEKEY'], verbose=False)
    registered_contracts = list(filter(lambda x: x['address'] == to_normalized_address(contractaddress), a_data['contracts']))
    if verbose:
        click.echo(registered_contracts)
    if registered_contracts:
        click.echo(f'{ctx_obj["settings"]["INTERNAL_API_ENDPOINT"]}/swagger/{to_normalized_address(contractaddress)}/?key={ctx_obj["settings"]["MATICVIGIL_API_KEY"]}')
    else:
        click.echo(f'Contract {contractaddress} not registered on MaticVigil')


def _gen_compilers_list(l):
    for k in l:
        yield click.style(f'{k+1}: {l[k]["full"]}\n', fg='cyan')


if __name__ == '__main__':
    cli()
