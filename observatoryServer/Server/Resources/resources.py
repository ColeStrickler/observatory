from flask_restful import Resource, reqparse
import json


class Endpoint_API(Resource):
    parser = reqparse.RequestParser()

    # This field is in all, we will use this to know how to parse correctly
    parser.add_argument('Type',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    # Parse FileParseEvent Fields
    parser.add_argument('File',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('File Size',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('MD5',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('SHA-1',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('SHA-256',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Sections',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Imports',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Strings',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Architecture',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Errors',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    # File Event Fields
    parser.add_argument('Timestamp',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('DataPath',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Process',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Action',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    # Network Event Fields
    parser.add_argument('Destination Ip',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Port',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    # Process Event Fields
    parser.add_argument('ProcessId',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('ParentProcess',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Parent ProcessId',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    # Image Load Event
    parser.add_argument('Load Base',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Load Image',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    # Thread Event
    parser.add_argument('ThreadId',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    # Remote Thread Event
    parser.add_argument('Creator Process',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Target Process',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Target ProcessId',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    # Object Callback Event
    parser.add_argument('Handle ProcessId',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )
    parser.add_argument('Handle Process',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    parser.add_argument('test',
                        type=str,
                        required=False,
                        help='This field cannot be blank.'
                        )

    def post(self):
        data = Endpoint_API.parser.parse_args()

        type = data['Type']
        print(type)

        if type == "FileParseEvent":

            pass
        elif type == "ParseFileEvent":

            pass
        elif type == "ParseNetworkEvent":

            pass
        elif type == "ParseProcessEvent":
            Timestamp = data['Timestamp']
            ProcessId = data['ProcessId']
            File = data['File']
            ParentPid = data['Parent ProcessId']
            ParentProcess = data['ParentProcess']
            print(f"Timestamp: {Timestamp}, Image File: {File}, PID: {ProcessId}, ParentProcess: {ParentProcess}, ParentPid: {ParentPid}")

        elif type == "ParseImageLoadEvent":

            pass
        elif type == "ParseThreadEvent":

            pass
        elif type == "ParseRemoteThreadEvent":

            pass
        elif type == "ParseRegistryEvent":

            pass
        elif type == "ParseObjectCallbackEvent":

            pass
        else:
            pass
        return 200
