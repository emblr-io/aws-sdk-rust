// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Use this structure to input your script code for the canary. This structure contains the Lambda handler with the location where the canary should start running the script. If the script is stored in an Amazon S3 bucket, the bucket name, key, and version are also included. If the script was passed into the canary directly, the script code is contained in the value of <code>Zipfile</code>.</p>
/// <p>If you are uploading your canary scripts with an Amazon S3 bucket, your zip file should include your script in a certain folder structure.</p>
/// <ul>
/// <li>
/// <p>For Node.js canaries, the folder structure must be <code>nodejs/node_modules/<i>myCanaryFilename.js</i> </code> For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_WritingCanary_Nodejs.html#CloudWatch_Synthetics_Canaries_package">Packaging your Node.js canary files</a></p></li>
/// <li>
/// <p>For Python canaries, the folder structure must be <code>python/<i>myCanaryFilename.py</i> </code> or <code>python/<i>myFolder/myCanaryFilename.py</i> </code> For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Synthetics_Canaries_WritingCanary_Python.html#CloudWatch_Synthetics_Canaries_WritingCanary_Python_package">Packaging your Python canary files</a></p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CanaryCodeInput {
    /// <p>If your canary script is located in Amazon S3, specify the bucket name here. Do not include <code>s3://</code> as the start of the bucket name.</p>
    pub s3_bucket: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon S3 key of your script. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingObjects.html">Working with Amazon S3 Objects</a>.</p>
    pub s3_key: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon S3 version ID of your script.</p>
    pub s3_version: ::std::option::Option<::std::string::String>,
    /// <p>If you input your canary script directly into the canary instead of referring to an Amazon S3 location, the value of this parameter is the base64-encoded contents of the .zip file that contains the script. It must be smaller than 225 Kb.</p>
    /// <p>For large canary scripts, we recommend that you use an Amazon S3 location instead of inputting it directly with this parameter.</p>
    pub zip_file: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>The entry point to use for the source code when running the canary. For canaries that use the <code>syn-python-selenium-1.0</code> runtime or a <code>syn-nodejs.puppeteer</code> runtime earlier than <code>syn-nodejs.puppeteer-3.4</code>, the handler must be specified as <code> <i>fileName</i>.handler</code>. For <code>syn-python-selenium-1.1</code>, <code>syn-nodejs.puppeteer-3.4</code>, and later runtimes, the handler can be specified as <code> <i>fileName</i>.<i>functionName</i> </code>, or you can specify a folder where canary scripts reside as <code> <i>folder</i>/<i>fileName</i>.<i>functionName</i> </code>.</p>
    pub handler: ::std::string::String,
}
impl CanaryCodeInput {
    /// <p>If your canary script is located in Amazon S3, specify the bucket name here. Do not include <code>s3://</code> as the start of the bucket name.</p>
    pub fn s3_bucket(&self) -> ::std::option::Option<&str> {
        self.s3_bucket.as_deref()
    }
    /// <p>The Amazon S3 key of your script. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingObjects.html">Working with Amazon S3 Objects</a>.</p>
    pub fn s3_key(&self) -> ::std::option::Option<&str> {
        self.s3_key.as_deref()
    }
    /// <p>The Amazon S3 version ID of your script.</p>
    pub fn s3_version(&self) -> ::std::option::Option<&str> {
        self.s3_version.as_deref()
    }
    /// <p>If you input your canary script directly into the canary instead of referring to an Amazon S3 location, the value of this parameter is the base64-encoded contents of the .zip file that contains the script. It must be smaller than 225 Kb.</p>
    /// <p>For large canary scripts, we recommend that you use an Amazon S3 location instead of inputting it directly with this parameter.</p>
    pub fn zip_file(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.zip_file.as_ref()
    }
    /// <p>The entry point to use for the source code when running the canary. For canaries that use the <code>syn-python-selenium-1.0</code> runtime or a <code>syn-nodejs.puppeteer</code> runtime earlier than <code>syn-nodejs.puppeteer-3.4</code>, the handler must be specified as <code> <i>fileName</i>.handler</code>. For <code>syn-python-selenium-1.1</code>, <code>syn-nodejs.puppeteer-3.4</code>, and later runtimes, the handler can be specified as <code> <i>fileName</i>.<i>functionName</i> </code>, or you can specify a folder where canary scripts reside as <code> <i>folder</i>/<i>fileName</i>.<i>functionName</i> </code>.</p>
    pub fn handler(&self) -> &str {
        use std::ops::Deref;
        self.handler.deref()
    }
}
impl CanaryCodeInput {
    /// Creates a new builder-style object to manufacture [`CanaryCodeInput`](crate::types::CanaryCodeInput).
    pub fn builder() -> crate::types::builders::CanaryCodeInputBuilder {
        crate::types::builders::CanaryCodeInputBuilder::default()
    }
}

/// A builder for [`CanaryCodeInput`](crate::types::CanaryCodeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CanaryCodeInputBuilder {
    pub(crate) s3_bucket: ::std::option::Option<::std::string::String>,
    pub(crate) s3_key: ::std::option::Option<::std::string::String>,
    pub(crate) s3_version: ::std::option::Option<::std::string::String>,
    pub(crate) zip_file: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) handler: ::std::option::Option<::std::string::String>,
}
impl CanaryCodeInputBuilder {
    /// <p>If your canary script is located in Amazon S3, specify the bucket name here. Do not include <code>s3://</code> as the start of the bucket name.</p>
    pub fn s3_bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If your canary script is located in Amazon S3, specify the bucket name here. Do not include <code>s3://</code> as the start of the bucket name.</p>
    pub fn set_s3_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_bucket = input;
        self
    }
    /// <p>If your canary script is located in Amazon S3, specify the bucket name here. Do not include <code>s3://</code> as the start of the bucket name.</p>
    pub fn get_s3_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_bucket
    }
    /// <p>The Amazon S3 key of your script. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingObjects.html">Working with Amazon S3 Objects</a>.</p>
    pub fn s3_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 key of your script. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingObjects.html">Working with Amazon S3 Objects</a>.</p>
    pub fn set_s3_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_key = input;
        self
    }
    /// <p>The Amazon S3 key of your script. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/UsingObjects.html">Working with Amazon S3 Objects</a>.</p>
    pub fn get_s3_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_key
    }
    /// <p>The Amazon S3 version ID of your script.</p>
    pub fn s3_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 version ID of your script.</p>
    pub fn set_s3_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_version = input;
        self
    }
    /// <p>The Amazon S3 version ID of your script.</p>
    pub fn get_s3_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_version
    }
    /// <p>If you input your canary script directly into the canary instead of referring to an Amazon S3 location, the value of this parameter is the base64-encoded contents of the .zip file that contains the script. It must be smaller than 225 Kb.</p>
    /// <p>For large canary scripts, we recommend that you use an Amazon S3 location instead of inputting it directly with this parameter.</p>
    pub fn zip_file(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.zip_file = ::std::option::Option::Some(input);
        self
    }
    /// <p>If you input your canary script directly into the canary instead of referring to an Amazon S3 location, the value of this parameter is the base64-encoded contents of the .zip file that contains the script. It must be smaller than 225 Kb.</p>
    /// <p>For large canary scripts, we recommend that you use an Amazon S3 location instead of inputting it directly with this parameter.</p>
    pub fn set_zip_file(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.zip_file = input;
        self
    }
    /// <p>If you input your canary script directly into the canary instead of referring to an Amazon S3 location, the value of this parameter is the base64-encoded contents of the .zip file that contains the script. It must be smaller than 225 Kb.</p>
    /// <p>For large canary scripts, we recommend that you use an Amazon S3 location instead of inputting it directly with this parameter.</p>
    pub fn get_zip_file(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.zip_file
    }
    /// <p>The entry point to use for the source code when running the canary. For canaries that use the <code>syn-python-selenium-1.0</code> runtime or a <code>syn-nodejs.puppeteer</code> runtime earlier than <code>syn-nodejs.puppeteer-3.4</code>, the handler must be specified as <code> <i>fileName</i>.handler</code>. For <code>syn-python-selenium-1.1</code>, <code>syn-nodejs.puppeteer-3.4</code>, and later runtimes, the handler can be specified as <code> <i>fileName</i>.<i>functionName</i> </code>, or you can specify a folder where canary scripts reside as <code> <i>folder</i>/<i>fileName</i>.<i>functionName</i> </code>.</p>
    /// This field is required.
    pub fn handler(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.handler = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The entry point to use for the source code when running the canary. For canaries that use the <code>syn-python-selenium-1.0</code> runtime or a <code>syn-nodejs.puppeteer</code> runtime earlier than <code>syn-nodejs.puppeteer-3.4</code>, the handler must be specified as <code> <i>fileName</i>.handler</code>. For <code>syn-python-selenium-1.1</code>, <code>syn-nodejs.puppeteer-3.4</code>, and later runtimes, the handler can be specified as <code> <i>fileName</i>.<i>functionName</i> </code>, or you can specify a folder where canary scripts reside as <code> <i>folder</i>/<i>fileName</i>.<i>functionName</i> </code>.</p>
    pub fn set_handler(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.handler = input;
        self
    }
    /// <p>The entry point to use for the source code when running the canary. For canaries that use the <code>syn-python-selenium-1.0</code> runtime or a <code>syn-nodejs.puppeteer</code> runtime earlier than <code>syn-nodejs.puppeteer-3.4</code>, the handler must be specified as <code> <i>fileName</i>.handler</code>. For <code>syn-python-selenium-1.1</code>, <code>syn-nodejs.puppeteer-3.4</code>, and later runtimes, the handler can be specified as <code> <i>fileName</i>.<i>functionName</i> </code>, or you can specify a folder where canary scripts reside as <code> <i>folder</i>/<i>fileName</i>.<i>functionName</i> </code>.</p>
    pub fn get_handler(&self) -> &::std::option::Option<::std::string::String> {
        &self.handler
    }
    /// Consumes the builder and constructs a [`CanaryCodeInput`](crate::types::CanaryCodeInput).
    /// This method will fail if any of the following fields are not set:
    /// - [`handler`](crate::types::builders::CanaryCodeInputBuilder::handler)
    pub fn build(self) -> ::std::result::Result<crate::types::CanaryCodeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CanaryCodeInput {
            s3_bucket: self.s3_bucket,
            s3_key: self.s3_key,
            s3_version: self.s3_version,
            zip_file: self.zip_file,
            handler: self.handler.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "handler",
                    "handler was not specified but it is required when building CanaryCodeInput",
                )
            })?,
        })
    }
}
