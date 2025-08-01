// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateKmsKeyInput {
    /// <p>The name of the log group.</p>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub log_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. This must be a symmetric KMS key. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a> and <a href="https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html">Using Symmetric and Asymmetric Keys</a>.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the target for this operation. You must specify one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Specify the following ARN to have future <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetQueryResults.html">GetQueryResults</a> operations in this account encrypt the results with the specified KMS key. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:query-result:*</code></p></li>
    /// <li>
    /// <p>Specify the ARN of a log group to have CloudWatch Logs use the KMS key to encrypt log events that are ingested and stored by that log group. The log group ARN must be in the following format. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:log-group:<i>LOG_GROUP_NAME</i> </code></p></li>
    /// </ul>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub resource_identifier: ::std::option::Option<::std::string::String>,
}
impl AssociateKmsKeyInput {
    /// <p>The name of the log group.</p>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub fn log_group_name(&self) -> ::std::option::Option<&str> {
        self.log_group_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. This must be a symmetric KMS key. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a> and <a href="https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html">Using Symmetric and Asymmetric Keys</a>.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>Specifies the target for this operation. You must specify one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Specify the following ARN to have future <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetQueryResults.html">GetQueryResults</a> operations in this account encrypt the results with the specified KMS key. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:query-result:*</code></p></li>
    /// <li>
    /// <p>Specify the ARN of a log group to have CloudWatch Logs use the KMS key to encrypt log events that are ingested and stored by that log group. The log group ARN must be in the following format. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:log-group:<i>LOG_GROUP_NAME</i> </code></p></li>
    /// </ul>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub fn resource_identifier(&self) -> ::std::option::Option<&str> {
        self.resource_identifier.as_deref()
    }
}
impl AssociateKmsKeyInput {
    /// Creates a new builder-style object to manufacture [`AssociateKmsKeyInput`](crate::operation::associate_kms_key::AssociateKmsKeyInput).
    pub fn builder() -> crate::operation::associate_kms_key::builders::AssociateKmsKeyInputBuilder {
        crate::operation::associate_kms_key::builders::AssociateKmsKeyInputBuilder::default()
    }
}

/// A builder for [`AssociateKmsKeyInput`](crate::operation::associate_kms_key::AssociateKmsKeyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateKmsKeyInputBuilder {
    pub(crate) log_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_identifier: ::std::option::Option<::std::string::String>,
}
impl AssociateKmsKeyInputBuilder {
    /// <p>The name of the log group.</p>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub fn log_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the log group.</p>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub fn set_log_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_name = input;
        self
    }
    /// <p>The name of the log group.</p>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub fn get_log_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_name
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. This must be a symmetric KMS key. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a> and <a href="https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html">Using Symmetric and Asymmetric Keys</a>.</p>
    /// This field is required.
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. This must be a symmetric KMS key. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a> and <a href="https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html">Using Symmetric and Asymmetric Keys</a>.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS key to use when encrypting log data. This must be a symmetric KMS key. For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html#arn-syntax-kms">Amazon Resource Names</a> and <a href="https://docs.aws.amazon.com/kms/latest/developerguide/symmetric-asymmetric.html">Using Symmetric and Asymmetric Keys</a>.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>Specifies the target for this operation. You must specify one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Specify the following ARN to have future <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetQueryResults.html">GetQueryResults</a> operations in this account encrypt the results with the specified KMS key. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:query-result:*</code></p></li>
    /// <li>
    /// <p>Specify the ARN of a log group to have CloudWatch Logs use the KMS key to encrypt log events that are ingested and stored by that log group. The log group ARN must be in the following format. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:log-group:<i>LOG_GROUP_NAME</i> </code></p></li>
    /// </ul>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub fn resource_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the target for this operation. You must specify one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Specify the following ARN to have future <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetQueryResults.html">GetQueryResults</a> operations in this account encrypt the results with the specified KMS key. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:query-result:*</code></p></li>
    /// <li>
    /// <p>Specify the ARN of a log group to have CloudWatch Logs use the KMS key to encrypt log events that are ingested and stored by that log group. The log group ARN must be in the following format. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:log-group:<i>LOG_GROUP_NAME</i> </code></p></li>
    /// </ul>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub fn set_resource_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_identifier = input;
        self
    }
    /// <p>Specifies the target for this operation. You must specify one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>Specify the following ARN to have future <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_GetQueryResults.html">GetQueryResults</a> operations in this account encrypt the results with the specified KMS key. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:query-result:*</code></p></li>
    /// <li>
    /// <p>Specify the ARN of a log group to have CloudWatch Logs use the KMS key to encrypt log events that are ingested and stored by that log group. The log group ARN must be in the following format. Replace <i>REGION</i> and <i>ACCOUNT_ID</i> with your Region and account ID.</p>
    /// <p><code>arn:aws:logs:<i>REGION</i>:<i>ACCOUNT_ID</i>:log-group:<i>LOG_GROUP_NAME</i> </code></p></li>
    /// </ul>
    /// <p>In your <code>AssociateKmsKey</code> operation, you must specify either the <code>resourceIdentifier</code> parameter or the <code>logGroup</code> parameter, but you can't specify both.</p>
    pub fn get_resource_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_identifier
    }
    /// Consumes the builder and constructs a [`AssociateKmsKeyInput`](crate::operation::associate_kms_key::AssociateKmsKeyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::associate_kms_key::AssociateKmsKeyInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::associate_kms_key::AssociateKmsKeyInput {
            log_group_name: self.log_group_name,
            kms_key_id: self.kms_key_id,
            resource_identifier: self.resource_identifier,
        })
    }
}
