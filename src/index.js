import React from "react";
import ReactDOM from "react-dom";
import { Alert, Tabs, message, Form, Row, List, Icon, Input, Button } from 'antd';
const { parse: parseUrl } = require('url');
import multihash from 'multihashes';
import CID from 'cids';
import styles from './global.css';
import "@babel/polyfill";

const TabPane = Tabs.TabPane;
const FormItem = Form.Item;

const TYPE_TAG_DNS = 15001;
const TYPE_TAG_WWW = 15002;
const CID_MIME_CODEC_PREFIX = 'mime/';

const REMAP_FIELDS = ['pubName', 'subName', 'url'];
const DECODE_URL_FIELDS = ['url2Decode'];

let safeApp = null;

const appInfo = {
    id     : 'net.maidsafe.remapSubName',
    name   : 'Remap subName',
    vendor : 'MaidSafe.net Ltd'
};

const authoriseApp = async () =>
{
    if ( safeApp !== null && safeApp.isNetStateConnected() ) return;

    console.log( 'Connecting to the network...' );
    safeApp = await window.safe.initialiseApp( appInfo );
    console.log( 'Authorising application...' );
    const authReqUri = await safeApp.auth.genAuthUri();
    const authUri = await window.safe.authorise( authReqUri );
    await safeApp.auth.loginFromUri( authUri );
    console.log( 'Signed in...' );

    if ( ! safeExperimentsEnabled )
    {
      message.error('The experimental APIs are disabled, please enable them from the SAFE Browser');
    }
};

const reqSharedMd = async (nameAndTag) =>
{
    try {
      const sharedMdReqUri = await safeApp.auth.genShareMDataUri([ {
        typeTag: nameAndTag.typeTag,
        name: nameAndTag.name,
        perms: ['Update'],
      } ]);
      const connUri = await window.safe.authorise( sharedMdReqUri );
      await safeApp.auth.loginFromUri( connUri );
    } catch (err) {
      throw Error('Failed to get permissions to update the PublicName container');
    }
};

function hasErrors(fieldsError) {
    return Object.keys(fieldsError).some(field => fieldsError[field]);
}

class MainPanel extends React.Component {
  state = {
      remappedMsg: '',
      decodedMsg: '',
  }

  componentDidMount() {
    // To disabled submit button at the beginning.
    this.props.form.validateFields();
  }

  remap = async (pubName, subName, url) => {
    try{
      await authoriseApp();
      const resource = await safeApp.fetch(url);
      console.log("TARGET RESOURCE TYPE:", resource.resourceType);
      const nameAndTag = await resource.content.getNameAndTag();
      let target = nameAndTag.name;
      console.log("TYPE TAG:", nameAndTag.typeTag);
      if (nameAndTag.typeTag !== TYPE_TAG_WWW) {
          target = await resource.content.serialise();
      }

      const addr = await safeApp.crypto.sha3Hash(pubName);
      const pubNameMd = await safeApp.mutableData.newPublic(addr, TYPE_TAG_DNS);
      const pubNameMdNameAndTag = await pubNameMd.getNameAndTag();
      await reqSharedMd(pubNameMdNameAndTag); // request permissions to mutation subName entry
      const mut = await safeApp.mutableData.newMutation();
      const current = await pubNameMd.get(subName);
      await mut.update(subName, target, current.version + 1);
      await pubNameMd.applyEntriesMutation(mut);
      this.setState( {
        remappedMsg: `Successfully remapped 'safe://${subName}.${pubName}' to same location targetted by '${url}'`,
        remappedResult: 'success',
      });

      this.props.form.setFieldsValue({
        pubName: null,
        subName: null,
        url: null
      });

    } catch (err) {
      console.error(err);
      this.setState( {
        remappedMsg: `Failed to remap 'safe://'${subName}.${pubName}': ${err.message}`,
        remappedResult: 'error',
      });
    }
  }

  decodeUrl = async (url) =>
  {
    let decodedMsg = '';
    try {
      await authoriseApp()

      const parsedUrl = parseUrl(url);
      if (!parsedUrl.protocol) throw Error('Invalid XOR-URL');

      const hostParts = parsedUrl.hostname.split('.');
      const publicName = hostParts.pop(); // last one is 'publicName'
      const subName = hostParts.join('.'); // all others are the 'subName'
      console.log("DECODING:", url);

      const resource = await safeApp.fetch(url);
      console.log("TARGET RESOURCE TYPE:", resource.resourceType);

      let type;
      switch (resource.resourceType) {
        case 'NFS':
          type = 'NFS container';
          break;
        case 'RDF':
          type = 'RDF resource';
          break;
        case 'MD':
          type = 'MutableData';
          break;
        case 'IMMD':
          type = 'ImmutableData';
          break;
        default:
          type = 'UNKNOWN';
      }

      decodedMsg = [
        ['Information about: ', url],
        `Targeted resource type: ${type}`
      ];

      if (subName.length === 0) {
        // this is effectively a XOR-URL
        const cid = new CID(publicName);
        console.log("CID VERSION:", cid.version);
        console.log("CID ENCODING BASE: ?????");
        const encodedHash = multihash.decode(cid.multihash);
        const address = encodedHash.digest;
        console.log("TYPE TAG:", parsedUrl.port);
        console.log("XORNAME:", `0x${address.toString('hex')}`)
        console.log("XORNAME length:", encodedHash.length);
        console.log("HASH:", encodedHash.name);
        const codec = cid.codec.replace(CID_MIME_CODEC_PREFIX, '');
        console.log("ENCODED CONTENT TYPE:", codec);
        decodedMsg = decodedMsg.concat([
          `Type tag: ${parsedUrl.port || 'NONE'}`,
          `XoR Name: 0x${address.toString('hex')}`,
          `XoR Name length: ${encodedHash.length}`,
          `Content type: ${codec === 'raw' ? 'NONE' : codec}`,
          `Hash type: ${encodedHash.name}`,
          `CID version: ${cid.version}`,
        ]);
      } else {
        const nameAndTag = await resource.content.getNameAndTag();
        console.log("TYPE TAG:", nameAndTag.typeTag);
        console.log("XORNAME:", `0x${nameAndTag.name.buffer.toString('hex')}`);
        console.log("XORNAME length:", nameAndTag.name.length);
        console.log("XOR-URL:", nameAndTag.xorUrl);
        decodedMsg = decodedMsg.concat([
          `Type tag: ${nameAndTag.typeTag}`,
          `XoR Name: 0x${nameAndTag.name.buffer.toString('hex')}`,
          `XoR Name length: ${nameAndTag.name.length}`,
          `XoR-URL: ${nameAndTag.xorUrl}`,
        ]);
      }

      // if there is a path in the URL let's show info about the file
      console.log("URL PATH:", resource.parsedPath);
      if (resource.parsedPath) {
        decodedMsg.push(`URL path: ${resource.parsedPath}`);
        try {
          if (resource.resourceType === 'NFS') {
            const emulation = resource.content.emulateAs(resource.resourceType);
            const file = await emulation.fetch(resource.parsedPath.replace(/^\//, ''));
            const filesize = await file.size();
            decodedMsg = decodedMsg.concat([
              `File size: ${filesize} bytes`,
              `File's version: ${file.version}`,
              `File's XoR Name: 0x${file.dataMapName.buffer.toString('hex')}`,
              `File's creation timestamp: ${file.created}`,
              `File's modification timestamp: ${file.modified}`,
              `File's user metadata: ${file.userMetadata.toString()}`,
            ])
          }
        } catch (err) {
          console.error("Failed to read file's info from URL path:", err);
        }
      }

      this.props.form.setFieldsValue({
        url2Decode: null,
      });

    } catch (err) {
      console.error(err);
      decodedMsg = `Failed to decode '${url}': ${err.message}`;
    }

    this.setState({ decodedMsg });
  }

  handleRemap = (e) => {
    e.preventDefault();
    this.props.form.validateFields(REMAP_FIELDS, (err, values) => {
      if (!err) {
        const values = this.props.form.getFieldsValue(REMAP_FIELDS);
        console.log('Received values of form: ', values);
        this.remap(values.pubName, values.subName, values.url);
      } else {
        console.error("ERROR:", err)
      }
    });
  }

  handleDecodeUrl = (e) => {
    e.preventDefault();
    this.props.form.validateFields(DECODE_URL_FIELDS, (err, values) => {
      if (!err) {
        const values = this.props.form.getFieldsValue(DECODE_URL_FIELDS);
        console.log('Received values of form: ', values);
        this.decodeUrl(values.url2Decode);
      } else {
        console.error("ERROR:", err)
      }
    });
  }

  render() {
    const { getFieldDecorator, getFieldsError, getFieldError, isFieldTouched } = this.props.form;

    // Only show error after a field is touched.
    const pubNameError = isFieldTouched('pubName') && getFieldError('pubName');
    const subNameError = isFieldTouched('subName') && getFieldError('subName');
    const urlError = isFieldTouched('url') && getFieldError('url');
    const url2DecodeError = isFieldTouched('url2Decode') && getFieldError('url2Decode');

    return (
      <div className={styles.cardContainer}>
        <Tabs type="card">
          <TabPane tab="safe-URL Analyser" key="2">

            <Form layout="inline" onSubmit={this.handleDecodeUrl}>
              <FormItem
                validateStatus={url2DecodeError ? 'error' : ''}
                help={url2DecodeError || ''}
              >
                {getFieldDecorator('url2Decode', {
                  rules: [{ required: true, message: 'Please enter the URL to analyse!' }],
                })(
                  <Input prefix={<Icon type="link" style={{ color: 'rgba(0,0,0,.25)' }} />} placeholder="XOR-URL / publicName-URL" />
                )}
              </FormItem>
              <FormItem>
                <Button
                  type="primary"
                  htmlType="submit"
                  disabled={hasErrors(getFieldsError(['url2Decode']))}
                >
                  Analyse URL
                </Button>
              </FormItem>
            </Form>
            <br/>
            {Array.isArray(this.state.decodedMsg) ?
                (<List style={{ margin: '20px' }}
                  split={false}
                  header={
                    <span><b>
                      {this.state.decodedMsg[0][0]}
                      <a href={this.state.decodedMsg[0][1]} target='_blank'>
                        {this.state.decodedMsg[0][1]}
                      </a>
                    </b></span>
                  }
                  dataSource={this.state.decodedMsg.slice(1)}
                  renderItem={item => (<List.Item>{item}</List.Item>)}
                />)
              : this.state.decodedMsg &&
                <Alert
                  closable
                  message={this.state.decodedMsg}
                  type="error"
                />
            }

          </TabPane>
          <TabPane tab="Remap a subName" key="1">

            <Form layout="inline" onSubmit={this.handleRemap}>
              <Row>
                <FormItem
                  validateStatus={pubNameError ? 'error' : ''}
                  help={pubNameError || ''}
                >
                  {getFieldDecorator('pubName', {
                    rules: [{ required: true, message: 'Please enter the publicName!' }],
                  })(
                    <Input placeholder="PublicName" />
                  )}
                </FormItem>
                <FormItem
                  validateStatus={subNameError ? 'error' : ''}
                  help={subNameError || ''}
                >
                  {getFieldDecorator('subName', {
                    rules: [{ required: true, message: 'Please enter the SubName to remap!' }],
                  })(
                    <Input placeholder="SubName" />
                  )}
                </FormItem>
              </Row>
              <Row>
                <FormItem
                  validateStatus={urlError ? 'error' : ''}
                  help={urlError || ''}
                >
                  {getFieldDecorator('url', {
                    rules: [{ required: true, message: 'Please enter the URL of the targetting service to remap!' }],
                  })(
                    <Input
                      prefix={<Icon type="link" style={{ color: 'rgba(0,0,0,.25)' }} />}
                      placeholder="Target XOR-URL / publicName-URL" />
                  )}
                </FormItem>
                <FormItem>
                  <Button
                    type="primary"
                    htmlType="submit"
                    disabled={hasErrors(getFieldsError(REMAP_FIELDS))}
                  >
                    Remap subName
                  </Button>
                </FormItem>
              </Row>
            </Form>
            {this.state.remappedMsg ?
              <Alert
                closable
                message={this.state.remappedMsg}
                type={this.state.remappedResult}
              />
              : null
            }

          </TabPane>
        </Tabs>
      </div>
    );
  }
}

const WrappedMainPanel = Form.create()(MainPanel);

var mountNode = document.getElementById("app");
ReactDOM.render(<WrappedMainPanel />, mountNode);
