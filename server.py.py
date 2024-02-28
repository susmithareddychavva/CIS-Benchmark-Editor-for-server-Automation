from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import xml.etree.ElementTree as ET

app = Flask(__name__)
CORS(app)


unixcheck_path = "C:\\Users\\csusmitha\\Documents\\dca-compliance-content\\checks\\unixchecklibrary"
wincheck_path = "C:\\Users\\csusmitha\\Documents\\dca-compliance-content\\checks\\winchecklibrary"

post_remediate_rules = [] 
def get_check_data(folder_path):
    check_data = {}

    def extract_check_data_from_folder(folder_path):
        for dir_root, dirs, files in os.walk(folder_path):
            for dir in dirs:
                if dir.startswith("ovalcom."):
                    subfolder_path = os.path.join(dir_root, dir)
                    config_path = os.path.join(subfolder_path, "config.xml")

                    try:
                        tree = ET.parse(config_path)
                        root = tree.getroot()

                        check_name = root.find(".//checkName").text
                        check_guid = root.find(".//checkGUID").text

                        
                        check_set_argument_count, check_get_argument_count = get_check_argument_count(subfolder_path)
                        check_data[check_name] = (check_guid, check_set_argument_count, check_get_argument_count)
                    except Exception as e:
                        print(f"Error processing {config_path}: {e}")

    extract_check_data_from_folder(folder_path)

    return check_data


def get_check_names(platform):
    check_data = {}

    if platform == 'unix':
        check_data.update(get_check_data(unixcheck_path))
    elif platform == 'windows':
        check_data.update(get_check_data(wincheck_path))
    else:
        return jsonify(error="Invalid platform specified")

    return check_data


def get_check_argument_count(folder_path):
    check_set_argument_count = 0
    check_get_argument_count = 0

    for dir_root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.endswith(".xml"):
                file_path = os.path.join(dir_root, file)
                tree = ET.parse(file_path)
                root = tree.getroot()

                check_set_arguments = root.findall(".//checkSetArguments")
                check_get_arguments = root.findall(".//checkGetArguments")

                for check_set_argument in check_set_arguments:
                    check_set_argument_count += len(check_set_argument)

                for check_get_argument in check_get_arguments:
                    check_get_argument_count += len(check_get_argument)

    return check_set_argument_count, check_get_argument_count


@app.route('/get_check_names', methods=['GET'])
def get_check_names_route():
    platform = request.args.get('platform', 'unix')
    check_data = get_check_names(platform)
    return jsonify(list(check_data.keys()))


@app.route('/get_check_guids', methods=['POST'])
def get_check_guids_route():
    check_names = request.json.get('checkNames', [])
    platform = request.json.get('platform', 'unix')

    check_data = get_check_names(platform)

    check_guids = [check_data.get(check_name, '') for check_name in check_names]

    return jsonify(check_guids)


@app.route('/get_check_argument_count', methods=['GET'])
def get_check_argument_count_route():
    platform = request.args.get('platform', 'unix')
    folder_path = unixcheck_path if platform == 'unix' else wincheck_path

    check_set_argument_count, check_get_argument_count = get_check_argument_count(folder_path)

    return jsonify({
        "checkSetArgumentCount": check_set_argument_count,
        "checkGetArgumentCount": check_get_argument_count
    })


@app.route('/get_check_argument_count_by_name', methods=['GET'])
def get_check_argument_count_by_name_route():
    platform = request.args.get('platform', 'unix')
    folder_path = unixcheck_path if platform == 'unix' else wincheck_path

    
    check_data = get_check_data(folder_path)

    
    check_argument_count_by_name = {}

    
    for check_name, check_info in check_data.items():
      
        check_set_argument_count, check_get_argument_count = check_info[1], check_info[2]

        
        check_argument_count_by_name[check_name] = {
            "checkSetArgumentCount": check_set_argument_count,
            "checkGetArgumentCount": check_get_argument_count
        }

    
    return jsonify(check_argument_count_by_name)


@app.route('/save_rule', methods=['POST'])
def save_rule():
    rule_data = request.json

    # In a production environment, you would want to store this data in a database
    post_remediate_rules.append(rule_data)

    return jsonify(message="Rule saved successfully")

if __name__ == '__main__':
    app.run(debug=True)
