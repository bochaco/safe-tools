import React from "react";
import ReactDOM from "react-dom";
import { Alert, Tabs, message, Form, Row, List, Icon, Input, Button } from 'antd';
const { parse: parseUrl } = require('url');
import multihash from 'multihashes';
import CID from 'cids';
import styles from './global.css';
import "@babel/polyfill";

const { TextArea } = Input;

const TabPane = Tabs.TabPane;
const FormItem = Form.Item;

const TYPE_TAG_DNS = 15001;
const TYPE_TAG_WWW = 15002;
const CID_MIME_CODEC_PREFIX = 'mime/';

const REMAP_FIELDS = ['pubName', 'subName', 'url'];
const DECODE_URL_FIELDS = ['url2Decode'];
const JSON_2_MD_FIELDS = ['typeTag', 'json'];
const GEN_XOR_URL_FIELDS = ['typeTag4Gen', 'xorName'];
const GEN_IMMD_XOR_URL_FIELDS = ['mimeType4Gen', 'immdXorName'];

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
        perms: ['Insert', 'Update'],
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
      newMdMsg: '',
      genXorUrlMsg: '',
      genImmdXorUrlMsg: '',
  }

  componentDidMount() {
    // To disabled submit button at the beginning.
    this.props.form.validateFields();
  }

  decodeUrl = async (url) =>
  {
    let decodedMsg = '';
    try {
      // replace any protocol with safe://
      url = `safe://${url.replace(/^.*:\/\//g, '')}`;
      const parsedUrl = parseUrl(url);
      if (!parsedUrl.protocol) throw Error('Invalid URL, it has no protocol');

      const hostParts = parsedUrl.hostname.split('.');
      const publicName = hostParts.pop(); // last one is 'publicName'
      const subName = hostParts.join('.'); // all others are the 'subName'
      console.log("Analysing URL:", url);

      await authoriseApp();
      let resource;
      try {
        resource = await safeApp.fetch(url);
        console.log("Resource found:", resource);
      } catch (err) {
        console.warn("Only the URL string will be decoded.",err);
      }

      const type = {
        'NFS' : 'NFS container',
        'RDF' : 'RDF resource',
        'MD'  : 'MutableData',
        'IMMD': 'ImmutableData',
      }[resource && resource.resourceType] || 'UNKNOWN';

      decodedMsg = [
        ['Information about', url, true],
        ['Targeted resource type', type]
      ];

      let justAPubNameUrl = (subName.length > 0);
      if (!justAPubNameUrl) {
        // this seems to be a XOR-URL
        try {
          const cid = new CID(publicName);
          const encodedHash = multihash.decode(cid.multihash);
          const address = encodedHash.digest;
          const codec = cid.codec.replace(CID_MIME_CODEC_PREFIX, '');
          decodedMsg = decodedMsg.concat([
            ['Type tag', (parsedUrl.port || 'NONE')],
            ['XoR Name', `0x${address.toString('hex')}`],
            ['XoR Name length', encodedHash.length],
            ['Encoded Content Type', (codec === 'raw' ? 'NONE' : codec)],
            ['Hash type', encodedHash.name],
            ['CID version', cid.version],
          ]);
        } catch (err) {
          // it must be a publicName-URL then
          justAPubNameUrl = true;
        }
      }

      if (resource && justAPubNameUrl) {
        const nameAndTag = await resource.content.getNameAndTag();
        decodedMsg = decodedMsg.concat([
          ['Type tag', nameAndTag.typeTag],
          ['XoR Name', `0x${nameAndTag.name.buffer.toString('hex')}`],
          ['XoR Name length', nameAndTag.name.length],
          ['XOR-URL', nameAndTag.xorUrl, true],
        ]);
      }

      // if there is a path in the URL let's show info about the file
      if (resource && resource.parsedPath) {
        decodedMsg.push(['URL path', resource.parsedPath]);
        if (resource.resourceType === 'NFS') {
          try {
            const emulation = resource.content.emulateAs(resource.resourceType);
            const file = await emulation.fetch(resource.parsedPath.replace(/^\//, ''));
            const filesize = await file.size();
            decodedMsg = decodedMsg.concat([
              ['- File size', `${filesize} bytes`],
              ['- File\'s version', file.version],
              ['- File\'s XoR Name', `0x${file.dataMapName.buffer.toString('hex')}`],
              ['- File\'s XoR Name length', file.dataMapName.length],
              ['- File\'s creation timestamp', file.created.toString()],
              ['- File\'s modification timestamp', file.modified.toString()],
              ['- File\'s user metadata', file.userMetadata.toString()],
            ]);
          } catch (err) {
            console.error("Failed to read file's info from URL path:", err);
          }
        }
      }

      this.props.form.setFieldsValue({
        url2Decode: null,
      });

    } catch (err) {
      console.error(err);
      decodedMsg = `Failed to analyse '${url}': ${err.message}`;
    }

    this.setState({ decodedMsg });
  }

  remap = async (pubName, subName, url) => {
    try {
      await authoriseApp();
      const resource = await safeApp.fetch(url);
      console.log("TARGET RESOURCE TYPE:", resource.resourceType);
      const nameAndTag = await resource.content.getNameAndTag();
      let target = nameAndTag.name;
      console.log("TARGET TYPE TAG:", nameAndTag.typeTag);
      if (nameAndTag.typeTag !== TYPE_TAG_WWW) {
          target = await resource.content.serialise();
      }

      const addr = await safeApp.crypto.sha3Hash(pubName);
      const pubNameMd = await safeApp.mutableData.newPublic(addr, TYPE_TAG_DNS);
      const pubNameMdNameAndTag = await pubNameMd.getNameAndTag();
      await reqSharedMd(pubNameMdNameAndTag); // request permissions to mutation subName entry
      const mut = await safeApp.mutableData.newMutation();
      try {
        // if the subName doesn't exist we'll insert it
        const current = await pubNameMd.get(subName);
        await mut.update(subName, target, current.version + 1);
      } catch(err) {
        // error -106 is Core error: Routing client error -> Requested entry not found
        if (err.code !== -106) {
          throw err;
        }
        await mut.insert(subName, target);
      }
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

  json2Md = async (typeTag, json) => {
    try {
      await authoriseApp();
      const parsedJson = JSON.parse(json);
      const pubNameMd = await safeApp.mutableData.newRandomPublic(typeTag);
      await pubNameMd.quickSetup(parsedJson);
      const nameAndTag = await pubNameMd.getNameAndTag();
      const newMdMsg = [
        ['XOR-URL', nameAndTag.xorUrl, true],
        ['Type tag', nameAndTag.typeTag],
        ['XoR Name', `0x${nameAndTag.name.buffer.toString('hex')}`],
        ['XoR Name length', nameAndTag.name.length],
        ['JSON stored', JSON.stringify(parsedJson, null, 2)],
      ];

      this.setState( {
        newMdMsg,
        newMdResult: 'success',
      });

      this.props.form.setFieldsValue({
        typeTag: null,
        json: null,
      });

    } catch (err) {
      console.error(err);
      this.setState( {
        newMdMsg: `Failed to store JSON in a MutableData: ${err.message}`,
        newMdResult: 'error',
      });
    }
  }

  genMdXorUrl = async (typeTag, xorName) => {
    try{
      await authoriseApp();
      const md = await safeApp.mutableData.newPublic(new Buffer(xorName, 'hex'), typeTag);
      const nameAndTag = await md.getNameAndTag();
      const genXorUrlMsg = [
        ['XOR-URL', nameAndTag.xorUrl, true],
        ['Type tag', nameAndTag.typeTag],
        ['XoR Name', `0x${nameAndTag.name.buffer.toString('hex')}`],
        ['XoR Name length', nameAndTag.name.length],
      ];

      this.setState( {
        genXorUrlMsg,
        genXorUrlResult: 'success',
      });

      this.props.form.setFieldsValue({
        typeTag4Gen: null,
        xorName: null,
      });

    } catch (err) {
      console.error(err);
      this.setState( {
        genXorUrlMsg: `Failed to generate MD XOR-URL: ${err.message}`,
        genXorUrlResult: 'error',
      });
    }
  }

  genImmdXorUrl = async (xorName, mimeType) => {
    try{
      await authoriseApp();
      const xorNameBuf = new Buffer(xorName, 'hex');
      const iDataReader = await safeApp.immutableData.fetch(xorNameBuf);
      const xorUrl = await iDataReader.getXorUrl(mimeType);
      const genImmdXorUrlMsg = [
        ['XOR-URL', xorUrl, true],
        ['Content type', mimeType],
        ['XoR Name', `0x${xorName}`],
        ['XoR Name length', xorNameBuf.length],
      ];

      this.setState( {
        genImmdXorUrlMsg,
        genImmdXorUrlResult: 'success',
      });

      this.props.form.setFieldsValue({
        mimeType4Gen: null,
        immdXorName: null,
      });

    } catch (err) {
      console.error(err);
      this.setState( {
        genImmdXorUrlMsg: `Failed to generate ImmD XOR-URL: ${err.message}`,
        genImmdXorUrlResult: 'error',
      });
    }
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

  handleJson2Md = (e) => {
    e.preventDefault();
    this.props.form.validateFields(JSON_2_MD_FIELDS, (err, values) => {
      if (!err) {
        const values = this.props.form.getFieldsValue(JSON_2_MD_FIELDS);
        console.log('Received values of form: ', values);
        this.json2Md(parseInt(values.typeTag), values.json);
      } else {
        console.error("ERROR:", err)
      }
    });
  }

  handleGenMdXorUrl = (e) => {
    e.preventDefault();
    this.props.form.validateFields(GEN_XOR_URL_FIELDS, (err, values) => {
      if (!err) {
        const values = this.props.form.getFieldsValue(GEN_XOR_URL_FIELDS);
        console.log('Received values of form: ', values);
        let typeTag = parseInt(values.typeTag4Gen);
        this.genMdXorUrl(typeTag, values.xorName);
      } else {
        console.error("ERROR:", err)
      }
    });
  }

  handleGenImmdXorUrl = (e) => {
    e.preventDefault();
    this.props.form.validateFields(GEN_IMMD_XOR_URL_FIELDS, (err, values) => {
      if (!err) {
        const values = this.props.form.getFieldsValue(GEN_IMMD_XOR_URL_FIELDS);
        console.log('Received values of form: ', values);
        this.genImmdXorUrl(values.immdXorName, values.mimeType4Gen);
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
    const typeTagError = isFieldTouched('typeTag') && getFieldError('typeTag');
    const jsonError = isFieldTouched('json') && getFieldError('json');
    const xorNameError = isFieldTouched('xorName') && getFieldError('xorName');
    const typeTag4GenError = isFieldTouched('typeTag4Gen') && getFieldError('typeTag4Gen');
    const immdXorNameError = isFieldTouched('immdXorName') && getFieldError('immdXorName');
    const mimeType4GenError = isFieldTouched('mimeType4Gen') && getFieldError('mimeType4Gen');

    return (
      <div className={styles.cardContainer}>
        <Tabs type="card">
          <TabPane tab="safe-URL Analyser" key="1">

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
                  dataSource={this.state.decodedMsg}
                  renderItem={item => (
                    <List.Item>
                      <b><span style={{ paddingRight: '1em' }}>{item[0]}:</span></b>
                      {item[2] ?
                        <a href={item[1]} target='_blank'>
                          {item[1]}
                        </a>
                        : item[1]
                      }
                    </List.Item>
                  )}
                />)
              : this.state.decodedMsg &&
                <Alert
                  closable
                  message={this.state.decodedMsg}
                  type="error"
                />
            }

          </TabPane>
          <TabPane tab="Remap a subName" key="2">

            <Form layout="inline" onSubmit={this.handleRemap}>
              <Row>
                <FormItem
                  validateStatus={pubNameError ? 'error' : ''}
                  help={pubNameError || ''}
                >
                  {getFieldDecorator('pubName', {
                    rules: [{ required: true, message: 'Please enter the publicName!' }],
                  })(
                    <Input placeholder="Existing PublicName" />
                  )}
                </FormItem>
                <FormItem
                  validateStatus={subNameError ? 'error' : ''}
                  help={subNameError || ''}
                >
                  {getFieldDecorator('subName', {
                    rules: [{ required: true, message: 'Please enter the SubName to remap!' }],
                  })(
                    <Input placeholder="Existing or new SubName" />
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
          <TabPane tab="JSON to MutableData" key="3">

            <Form layout="inline" onSubmit={this.handleJson2Md}>
              <Row>
                <FormItem
                  validateStatus={jsonError ? 'error' : ''}
                  help={jsonError || ''}
                >
                  {getFieldDecorator('json', {
                    rules: [{ required: true, message: 'Please enter the JSON!' }],
                  })(
                    <TextArea rows={7} placeholder="JSON" />
                  )}
                </FormItem>
              </Row>
              <Row>
                <FormItem
                  validateStatus={typeTagError ? 'error' : ''}
                  help={typeTagError || ''}
                >
                  {getFieldDecorator('typeTag', {
                    rules: [{ required: true, pattern: '^[0-9]+$', message: 'Please enter a number for the Type Tag!' }],
                  })(
                    <Input placeholder="Type Tag number" />
                  )}
                </FormItem>
                <FormItem>
                  <Button
                    type="primary"
                    htmlType="submit"
                    disabled={hasErrors(getFieldsError(JSON_2_MD_FIELDS))}
                  >
                    Create MutableData
                  </Button>
                </FormItem>
              </Row>
            </Form>
            <br/>
            {Array.isArray(this.state.newMdMsg) ?
                (<List style={{ margin: '20px' }}
                  split={false}
                  dataSource={this.state.newMdMsg}
                  renderItem={item => (
                    <List.Item>
                      <b><span style={{ paddingRight: '1em' }}>{item[0]}:</span></b>
                      {item[2] ?
                        <a href={item[1]} target='_blank'>
                          {item[1]}
                        </a>
                        : item[1]
                      }
                    </List.Item>
                  )}
                />)
              : this.state.newMdMsg &&
                <Alert
                  closable
                  message={this.state.newMdMsg}
                  type="error"
                />
            }

          </TabPane>
          <TabPane tab="Generate MD XOR-URL" key="4">

            <Form layout="inline" onSubmit={this.handleGenMdXorUrl}>
              <Row>
                <FormItem
                  validateStatus={xorNameError ? 'error' : ''}
                  help={xorNameError || ''}
                >
                  {getFieldDecorator('xorName', {
                    rules: [{ required: true, message: 'Please enter a MutableData XoR name!' }],
                  })(
                    <Input placeholder="MutableData XoR name (in hex)" />
                  )}
                </FormItem>
              </Row>
              <Row>
                <FormItem
                  validateStatus={typeTag4GenError ? 'error' : ''}
                  help={typeTag4GenError || ''}
                >
                  {getFieldDecorator('typeTag4Gen', {
                    rules: [{ required: true, pattern: '^[0-9]+$', message: 'Please enter a number for the Type Tag!' }],
                  })(
                    <Input placeholder="Type Tag number" />
                  )}
                </FormItem>
                <FormItem>
                  <Button
                    type="primary"
                    htmlType="submit"
                    disabled={hasErrors(getFieldsError(GEN_XOR_URL_FIELDS))}
                  >
                    Generate MD XOR-URL
                  </Button>
                </FormItem>
              </Row>
            </Form>
            <br/>
            {Array.isArray(this.state.genXorUrlMsg) ?
                (<List style={{ margin: '20px' }}
                  split={false}
                  dataSource={this.state.genXorUrlMsg}
                  renderItem={item => (
                    <List.Item>
                      <b><span style={{ paddingRight: '1em' }}>{item[0]}:</span></b>
                      {item[2] ?
                        <a href={item[1]} target='_blank'>
                          {item[1]}
                        </a>
                        : item[1]
                      }
                    </List.Item>
                  )}
                />)
              : this.state.genXorUrlMsg &&
                <Alert
                  closable
                  message={this.state.genXorUrlMsg}
                  type="error"
                />
            }

          </TabPane>

          <TabPane tab="Generate ImmD XOR-URL" key="5">

            <Form layout="inline" onSubmit={this.handleGenImmdXorUrl}>
              <Row>
                <FormItem
                  validateStatus={immdXorNameError ? 'error' : ''}
                  help={immdXorNameError || ''}
                >
                  {getFieldDecorator('immdXorName', {
                    rules: [{ required: true, message: 'Please enter an ImmutableData XoR name!' }],
                  })(
                    <Input placeholder="ImmutableData XoR name (in hex)" />
                  )}
                </FormItem>
              </Row>
              <Row>
                <FormItem
                  validateStatus={mimeType4GenError ? 'error' : ''}
                  help={mimeType4GenError || ''}
                >
                  {getFieldDecorator('mimeType4Gen', {
                    rules: [{ required: false, message: '(optional) Enter a mime type' }],
                  })(
                    <Input placeholder="(optional) Mime-Type" />
                  )}
                </FormItem>
                <FormItem>
                  <Button
                    type="primary"
                    htmlType="submit"
                    disabled={hasErrors(getFieldsError(GEN_IMMD_XOR_URL_FIELDS))}
                  >
                    Generate ImmD XOR-URL
                  </Button>
                </FormItem>
              </Row>
            </Form>
            <br/>
            {Array.isArray(this.state.genImmdXorUrlMsg) ?
                (<List style={{ margin: '20px' }}
                  split={false}
                  dataSource={this.state.genImmdXorUrlMsg}
                  renderItem={item => (
                    <List.Item>
                      <b><span style={{ paddingRight: '1em' }}>{item[0]}:</span></b>
                      {item[2] ?
                        <a href={item[1]} target='_blank'>
                          {item[1]}
                        </a>
                        : item[1]
                      }
                    </List.Item>
                  )}
                />)
              : this.state.genImmdXorUrlMsg &&
                <Alert
                  closable
                  message={this.state.genImmdXorUrlMsg}
                  type="error"
                />
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
