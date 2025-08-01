// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAdapterVersionOutput {
    /// <p>A string containing a unique ID for the adapter version being retrieved.</p>
    pub adapter_id: ::std::option::Option<::std::string::String>,
    /// <p>A string containing the adapter version that has been retrieved.</p>
    pub adapter_version: ::std::option::Option<::std::string::String>,
    /// <p>The time that the adapter version was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>List of the targeted feature types for the requested adapter version.</p>
    pub feature_types: ::std::option::Option<::std::vec::Vec<crate::types::FeatureType>>,
    /// <p>The status of the adapter version that has been requested.</p>
    pub status: ::std::option::Option<crate::types::AdapterVersionStatus>,
    /// <p>A message that describes the status of the requested adapter version.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>Specifies a dataset used to train a new adapter version. Takes a ManifestS3Objec as the value.</p>
    pub dataset_config: ::std::option::Option<crate::types::AdapterVersionDatasetConfig>,
    /// <p>The identifier for your AWS Key Management Service key (AWS KMS key). Used to encrypt your documents.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub output_config: ::std::option::Option<crate::types::OutputConfig>,
    /// <p>The evaluation metrics (F1 score, Precision, and Recall) for the requested version, grouped by baseline metrics and adapter version.</p>
    pub evaluation_metrics: ::std::option::Option<::std::vec::Vec<crate::types::AdapterVersionEvaluationMetric>>,
    /// <p>A set of tags (key-value pairs) that are associated with the adapter version.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetAdapterVersionOutput {
    /// <p>A string containing a unique ID for the adapter version being retrieved.</p>
    pub fn adapter_id(&self) -> ::std::option::Option<&str> {
        self.adapter_id.as_deref()
    }
    /// <p>A string containing the adapter version that has been retrieved.</p>
    pub fn adapter_version(&self) -> ::std::option::Option<&str> {
        self.adapter_version.as_deref()
    }
    /// <p>The time that the adapter version was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>List of the targeted feature types for the requested adapter version.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.feature_types.is_none()`.
    pub fn feature_types(&self) -> &[crate::types::FeatureType] {
        self.feature_types.as_deref().unwrap_or_default()
    }
    /// <p>The status of the adapter version that has been requested.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::AdapterVersionStatus> {
        self.status.as_ref()
    }
    /// <p>A message that describes the status of the requested adapter version.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>Specifies a dataset used to train a new adapter version. Takes a ManifestS3Objec as the value.</p>
    pub fn dataset_config(&self) -> ::std::option::Option<&crate::types::AdapterVersionDatasetConfig> {
        self.dataset_config.as_ref()
    }
    /// <p>The identifier for your AWS Key Management Service key (AWS KMS key). Used to encrypt your documents.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub fn output_config(&self) -> ::std::option::Option<&crate::types::OutputConfig> {
        self.output_config.as_ref()
    }
    /// <p>The evaluation metrics (F1 score, Precision, and Recall) for the requested version, grouped by baseline metrics and adapter version.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.evaluation_metrics.is_none()`.
    pub fn evaluation_metrics(&self) -> &[crate::types::AdapterVersionEvaluationMetric] {
        self.evaluation_metrics.as_deref().unwrap_or_default()
    }
    /// <p>A set of tags (key-value pairs) that are associated with the adapter version.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetAdapterVersionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAdapterVersionOutput {
    /// Creates a new builder-style object to manufacture [`GetAdapterVersionOutput`](crate::operation::get_adapter_version::GetAdapterVersionOutput).
    pub fn builder() -> crate::operation::get_adapter_version::builders::GetAdapterVersionOutputBuilder {
        crate::operation::get_adapter_version::builders::GetAdapterVersionOutputBuilder::default()
    }
}

/// A builder for [`GetAdapterVersionOutput`](crate::operation::get_adapter_version::GetAdapterVersionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAdapterVersionOutputBuilder {
    pub(crate) adapter_id: ::std::option::Option<::std::string::String>,
    pub(crate) adapter_version: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) feature_types: ::std::option::Option<::std::vec::Vec<crate::types::FeatureType>>,
    pub(crate) status: ::std::option::Option<crate::types::AdapterVersionStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) dataset_config: ::std::option::Option<crate::types::AdapterVersionDatasetConfig>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) output_config: ::std::option::Option<crate::types::OutputConfig>,
    pub(crate) evaluation_metrics: ::std::option::Option<::std::vec::Vec<crate::types::AdapterVersionEvaluationMetric>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetAdapterVersionOutputBuilder {
    /// <p>A string containing a unique ID for the adapter version being retrieved.</p>
    pub fn adapter_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.adapter_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string containing a unique ID for the adapter version being retrieved.</p>
    pub fn set_adapter_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.adapter_id = input;
        self
    }
    /// <p>A string containing a unique ID for the adapter version being retrieved.</p>
    pub fn get_adapter_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.adapter_id
    }
    /// <p>A string containing the adapter version that has been retrieved.</p>
    pub fn adapter_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.adapter_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string containing the adapter version that has been retrieved.</p>
    pub fn set_adapter_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.adapter_version = input;
        self
    }
    /// <p>A string containing the adapter version that has been retrieved.</p>
    pub fn get_adapter_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.adapter_version
    }
    /// <p>The time that the adapter version was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the adapter version was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time that the adapter version was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// Appends an item to `feature_types`.
    ///
    /// To override the contents of this collection use [`set_feature_types`](Self::set_feature_types).
    ///
    /// <p>List of the targeted feature types for the requested adapter version.</p>
    pub fn feature_types(mut self, input: crate::types::FeatureType) -> Self {
        let mut v = self.feature_types.unwrap_or_default();
        v.push(input);
        self.feature_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of the targeted feature types for the requested adapter version.</p>
    pub fn set_feature_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FeatureType>>) -> Self {
        self.feature_types = input;
        self
    }
    /// <p>List of the targeted feature types for the requested adapter version.</p>
    pub fn get_feature_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FeatureType>> {
        &self.feature_types
    }
    /// <p>The status of the adapter version that has been requested.</p>
    pub fn status(mut self, input: crate::types::AdapterVersionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the adapter version that has been requested.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AdapterVersionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the adapter version that has been requested.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AdapterVersionStatus> {
        &self.status
    }
    /// <p>A message that describes the status of the requested adapter version.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message that describes the status of the requested adapter version.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>A message that describes the status of the requested adapter version.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>Specifies a dataset used to train a new adapter version. Takes a ManifestS3Objec as the value.</p>
    pub fn dataset_config(mut self, input: crate::types::AdapterVersionDatasetConfig) -> Self {
        self.dataset_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies a dataset used to train a new adapter version. Takes a ManifestS3Objec as the value.</p>
    pub fn set_dataset_config(mut self, input: ::std::option::Option<crate::types::AdapterVersionDatasetConfig>) -> Self {
        self.dataset_config = input;
        self
    }
    /// <p>Specifies a dataset used to train a new adapter version. Takes a ManifestS3Objec as the value.</p>
    pub fn get_dataset_config(&self) -> &::std::option::Option<crate::types::AdapterVersionDatasetConfig> {
        &self.dataset_config
    }
    /// <p>The identifier for your AWS Key Management Service key (AWS KMS key). Used to encrypt your documents.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for your AWS Key Management Service key (AWS KMS key). Used to encrypt your documents.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The identifier for your AWS Key Management Service key (AWS KMS key). Used to encrypt your documents.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub fn output_config(mut self, input: crate::types::OutputConfig) -> Self {
        self.output_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub fn set_output_config(mut self, input: ::std::option::Option<crate::types::OutputConfig>) -> Self {
        self.output_config = input;
        self
    }
    /// <p>Sets whether or not your output will go to a user created bucket. Used to set the name of the bucket, and the prefix on the output file.</p>
    /// <p><code>OutputConfig</code> is an optional parameter which lets you adjust where your output will be placed. By default, Amazon Textract will store the results internally and can only be accessed by the Get API operations. With <code>OutputConfig</code> enabled, you can set the name of the bucket the output will be sent to the file prefix of the results where you can download your results. Additionally, you can set the <code>KMSKeyID</code> parameter to a customer master key (CMK) to encrypt your output. Without this parameter set Amazon Textract will encrypt server-side using the AWS managed CMK for Amazon S3.</p>
    /// <p>Decryption of Customer Content is necessary for processing of the documents by Amazon Textract. If your account is opted out under an AI services opt out policy then all unencrypted Customer Content is immediately and permanently deleted after the Customer Content has been processed by the service. No copy of of the output is retained by Amazon Textract. For information about how to opt out, see <a href="https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_ai-opt-out.html"> Managing AI services opt-out policy. </a></p>
    /// <p>For more information on data privacy, see the <a href="https://aws.amazon.com/compliance/data-privacy-faq/">Data Privacy FAQ</a>.</p>
    pub fn get_output_config(&self) -> &::std::option::Option<crate::types::OutputConfig> {
        &self.output_config
    }
    /// Appends an item to `evaluation_metrics`.
    ///
    /// To override the contents of this collection use [`set_evaluation_metrics`](Self::set_evaluation_metrics).
    ///
    /// <p>The evaluation metrics (F1 score, Precision, and Recall) for the requested version, grouped by baseline metrics and adapter version.</p>
    pub fn evaluation_metrics(mut self, input: crate::types::AdapterVersionEvaluationMetric) -> Self {
        let mut v = self.evaluation_metrics.unwrap_or_default();
        v.push(input);
        self.evaluation_metrics = ::std::option::Option::Some(v);
        self
    }
    /// <p>The evaluation metrics (F1 score, Precision, and Recall) for the requested version, grouped by baseline metrics and adapter version.</p>
    pub fn set_evaluation_metrics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AdapterVersionEvaluationMetric>>) -> Self {
        self.evaluation_metrics = input;
        self
    }
    /// <p>The evaluation metrics (F1 score, Precision, and Recall) for the requested version, grouped by baseline metrics and adapter version.</p>
    pub fn get_evaluation_metrics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AdapterVersionEvaluationMetric>> {
        &self.evaluation_metrics
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A set of tags (key-value pairs) that are associated with the adapter version.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A set of tags (key-value pairs) that are associated with the adapter version.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A set of tags (key-value pairs) that are associated with the adapter version.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAdapterVersionOutput`](crate::operation::get_adapter_version::GetAdapterVersionOutput).
    pub fn build(self) -> crate::operation::get_adapter_version::GetAdapterVersionOutput {
        crate::operation::get_adapter_version::GetAdapterVersionOutput {
            adapter_id: self.adapter_id,
            adapter_version: self.adapter_version,
            creation_time: self.creation_time,
            feature_types: self.feature_types,
            status: self.status,
            status_message: self.status_message,
            dataset_config: self.dataset_config,
            kms_key_id: self.kms_key_id,
            output_config: self.output_config,
            evaluation_metrics: self.evaluation_metrics,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
