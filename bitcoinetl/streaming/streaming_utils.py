from blockchainetl.jobs.exporters.console_item_exporter import ConsoleItemExporter
from blockchainetl.jobs.exporters.google_pubsub_item_exporter import GooglePubSubItemExporter
from blockchainetl.jobs.exporters.s3_item_exporter import AwsItemExporter

def get_item_exporter(output):
    if output is not None:
        type = determine_item_exporter_type(output=output)

        if type == "aws":
            bucket, path = get_bucket_and_path_from_aws_output(output)
            return AwsItemExporter(bucket=bucket, path=path)
        else:
            return GooglePubSubItemExporter(
                item_type_to_topic_mapping={
                    'block': output + '.blocks',
                    'transaction': output + '.transactions'
                },
                message_attributes=('item_id',))
    else:
        return ConsoleItemExporter()

def determine_item_exporter_type(output):
    if output is not None and output.startswith('s3://'):
        return "aws"


def get_bucket_and_path_from_aws_output(output):
    output = output.replace('s3://', '')
    bucket_and_path = output.split('/', 1)
    bucket = bucket_and_path[0]
    if len(bucket_and_path) > 1:
        path = bucket_and_path[1]
    else:
        path = ''
    return bucket, path
