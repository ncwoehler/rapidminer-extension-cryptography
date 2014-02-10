![Extension icon](src/main/resources/META-INF/icon.png) RapidMiner Cryptography Extension
===============================

A RapidMiner extension that adds operators for password-based file encryption and decryption and document encryption and decryption. It uses strong cryptography algorithms provided by the Bouncy Castle Crypto APIs (https://www.bouncycastle.org/).

In particular it adds four new operators:

 - Encrypt File (Password)
 - Decrypt File (Password)
 - Encrypt Document (Password)
 - Decrypt Document (Password)

![example process](screenshots/example_process.png)

## Unlimited Strength Jurisdiction Policy Files
For using strong algorithm strength the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files have to be installed for the Java VM RapidMiner is started with. The files can be downloaded from here: http://www.oracle.com/technetwork/java/javase/downloads/jce-7-download-432124.html

To install the Unlimited Strength Jurisdiction Policy Files extract the files from the downloaded archive and copy them to $PATH_TO_JRE/lib/security (e.g. "_C:\Program Files\RapidMiner\RapidMiner Studio\jre\lib\security_").

## Example Process

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<process version="6.0.002">
  <context>
    <input/>
    <output/>
    <macros/>
  </context>
  <operator activated="true" class="process" compatibility="6.0.002" expanded="true" name="Process">
    <process expanded="true">
      <operator activated="true" class="retrieve" compatibility="6.0.002" expanded="true" height="60" name="Retrieve Iris" width="90" x="45" y="75">
        <parameter key="repository_entry" value="//Samples/data/Iris"/>
      </operator>
      <operator activated="true" class="write_excel" compatibility="6.0.002" expanded="true" height="76" name="Write Excel" width="90" x="179" y="75"/>
      <operator activated="true" class="cryptography:pbe_encrypt_file" compatibility="1.0.001" expanded="true" height="60" name="Encrypt Iris.xls" width="90" x="313" y="75">
        <parameter key="password" value="7ATUvY3F9fs="/>
        <parameter key="base64" value="true"/>
      </operator>
      <operator activated="true" class="remember" compatibility="6.0.002" expanded="true" height="60" name="Remember" width="90" x="447" y="75">
        <parameter key="name" value="encrypted_iris"/>
        <parameter key="io_object" value="FileObject"/>
      </operator>
      <operator activated="true" class="text:read_document" compatibility="5.3.002" expanded="true" height="60" name="Read Document" width="90" x="581" y="75"/>
      <operator activated="true" class="recall" compatibility="6.0.002" expanded="true" height="60" name="Recall" width="90" x="45" y="255">
        <parameter key="name" value="encrypted_iris"/>
        <parameter key="io_object" value="FileObject"/>
      </operator>
      <operator activated="true" class="cryptography:pbe_decrypt_file" compatibility="1.0.001" expanded="true" height="60" name="Decryt Iris.xls" width="90" x="313" y="255">
        <parameter key="password" value="7ATUvY3F9fs="/>
        <parameter key="base64" value="true"/>
      </operator>
      <operator activated="true" class="read_excel" compatibility="6.0.002" expanded="true" height="60" name="Read Excel" width="90" x="514" y="255">
        <list key="annotations"/>
        <list key="data_set_meta_data_information"/>
      </operator>
      <operator activated="true" class="text:create_document" compatibility="5.3.002" expanded="true" height="60" name="Create Document" width="90" x="45" y="390">
        <parameter key="text" value="Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet."/>
      </operator>
      <operator activated="true" class="cryptography:pbe_encrypt_document" compatibility="1.0.001" expanded="true" height="60" name="Encrypt Document" width="90" x="313" y="390">
        <parameter key="password" value="7ATUvY3F9fs="/>
      </operator>
      <operator activated="true" class="multiply" compatibility="6.0.002" expanded="true" height="94" name="Multiply" width="90" x="447" y="390"/>
      <operator activated="true" class="cryptography:pbe_decrypt_document" compatibility="1.0.001" expanded="true" height="60" name="Decrypt Document" width="90" x="715" y="480">
        <parameter key="password" value="7ATUvY3F9fs="/>
      </operator>
      <connect from_op="Retrieve Iris" from_port="output" to_op="Write Excel" to_port="input"/>
      <connect from_op="Write Excel" from_port="file" to_op="Encrypt Iris.xls" to_port="file input"/>
      <connect from_op="Encrypt Iris.xls" from_port="file output" to_op="Remember" to_port="store"/>
      <connect from_op="Remember" from_port="stored" to_op="Read Document" to_port="file"/>
      <connect from_op="Read Document" from_port="output" to_port="result 1"/>
      <connect from_op="Recall" from_port="result" to_op="Decryt Iris.xls" to_port="file input"/>
      <connect from_op="Decryt Iris.xls" from_port="file output" to_op="Read Excel" to_port="file"/>
      <connect from_op="Read Excel" from_port="output" to_port="result 2"/>
      <connect from_op="Create Document" from_port="output" to_op="Encrypt Document" to_port="document_input"/>
      <connect from_op="Encrypt Document" from_port="document_output" to_op="Multiply" to_port="input"/>
      <connect from_op="Multiply" from_port="output 1" to_port="result 3"/>
      <connect from_op="Multiply" from_port="output 2" to_op="Decrypt Document" to_port="document_input"/>
      <connect from_op="Decrypt Document" from_port="document_output" to_port="result 4"/>
      <portSpacing port="source_input 1" spacing="0"/>
      <portSpacing port="sink_result 1" spacing="0"/>
      <portSpacing port="sink_result 2" spacing="162"/>
      <portSpacing port="sink_result 3" spacing="108"/>
      <portSpacing port="sink_result 4" spacing="90"/>
      <portSpacing port="sink_result 5" spacing="18"/>
    </process>
  </operator>
</process>
```
 
