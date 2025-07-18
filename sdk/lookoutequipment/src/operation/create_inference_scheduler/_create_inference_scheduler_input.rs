// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateInferenceSchedulerInput {
    /// <p>The name of the previously trained machine learning model being used to create the inference scheduler.</p>
    pub model_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the inference scheduler being created.</p>
    pub inference_scheduler_name: ::std::option::Option<::std::string::String>,
    /// <p>The interval (in minutes) of planned delay at the start of each inference segment. For example, if inference is set to run every ten minutes, the delay is set to five minutes and the time is 09:08. The inference scheduler will wake up at the configured interval (which, without a delay configured, would be 09:10) plus the additional five minute delay time (so 09:15) to check your Amazon S3 bucket. The delay provides a buffer for you to upload data at the same frequency, so that you don't have to stop and restart the scheduler when uploading new data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    pub data_delay_offset_in_minutes: ::std::option::Option<i64>,
    /// <p>How often data is uploaded to the source Amazon S3 bucket for the input data. The value chosen is the length of time between data uploads. For instance, if you select 5 minutes, Amazon Lookout for Equipment will upload the real-time data to the source bucket once every 5 minutes. This frequency also determines how often Amazon Lookout for Equipment runs inference on your data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    pub data_upload_frequency: ::std::option::Option<crate::types::DataUploadFrequency>,
    /// <p>Specifies configuration information for the input data for the inference scheduler, including delimiter, format, and dataset location.</p>
    pub data_input_configuration: ::std::option::Option<crate::types::InferenceInputConfiguration>,
    /// <p>Specifies configuration information for the output results for the inference scheduler, including the S3 location for the output.</p>
    pub data_output_configuration: ::std::option::Option<crate::types::InferenceOutputConfiguration>,
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source being used for the inference.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Provides the identifier of the KMS key used to encrypt inference scheduler data by Amazon Lookout for Equipment.</p>
    pub server_side_kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the request. If you do not set the client request token, Amazon Lookout for Equipment generates one.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Any tags associated with the inference scheduler.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateInferenceSchedulerInput {
    /// <p>The name of the previously trained machine learning model being used to create the inference scheduler.</p>
    pub fn model_name(&self) -> ::std::option::Option<&str> {
        self.model_name.as_deref()
    }
    /// <p>The name of the inference scheduler being created.</p>
    pub fn inference_scheduler_name(&self) -> ::std::option::Option<&str> {
        self.inference_scheduler_name.as_deref()
    }
    /// <p>The interval (in minutes) of planned delay at the start of each inference segment. For example, if inference is set to run every ten minutes, the delay is set to five minutes and the time is 09:08. The inference scheduler will wake up at the configured interval (which, without a delay configured, would be 09:10) plus the additional five minute delay time (so 09:15) to check your Amazon S3 bucket. The delay provides a buffer for you to upload data at the same frequency, so that you don't have to stop and restart the scheduler when uploading new data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    pub fn data_delay_offset_in_minutes(&self) -> ::std::option::Option<i64> {
        self.data_delay_offset_in_minutes
    }
    /// <p>How often data is uploaded to the source Amazon S3 bucket for the input data. The value chosen is the length of time between data uploads. For instance, if you select 5 minutes, Amazon Lookout for Equipment will upload the real-time data to the source bucket once every 5 minutes. This frequency also determines how often Amazon Lookout for Equipment runs inference on your data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    pub fn data_upload_frequency(&self) -> ::std::option::Option<&crate::types::DataUploadFrequency> {
        self.data_upload_frequency.as_ref()
    }
    /// <p>Specifies configuration information for the input data for the inference scheduler, including delimiter, format, and dataset location.</p>
    pub fn data_input_configuration(&self) -> ::std::option::Option<&crate::types::InferenceInputConfiguration> {
        self.data_input_configuration.as_ref()
    }
    /// <p>Specifies configuration information for the output results for the inference scheduler, including the S3 location for the output.</p>
    pub fn data_output_configuration(&self) -> ::std::option::Option<&crate::types::InferenceOutputConfiguration> {
        self.data_output_configuration.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source being used for the inference.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>Provides the identifier of the KMS key used to encrypt inference scheduler data by Amazon Lookout for Equipment.</p>
    pub fn server_side_kms_key_id(&self) -> ::std::option::Option<&str> {
        self.server_side_kms_key_id.as_deref()
    }
    /// <p>A unique identifier for the request. If you do not set the client request token, Amazon Lookout for Equipment generates one.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Any tags associated with the inference scheduler.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateInferenceSchedulerInput {
    /// Creates a new builder-style object to manufacture [`CreateInferenceSchedulerInput`](crate::operation::create_inference_scheduler::CreateInferenceSchedulerInput).
    pub fn builder() -> crate::operation::create_inference_scheduler::builders::CreateInferenceSchedulerInputBuilder {
        crate::operation::create_inference_scheduler::builders::CreateInferenceSchedulerInputBuilder::default()
    }
}

/// A builder for [`CreateInferenceSchedulerInput`](crate::operation::create_inference_scheduler::CreateInferenceSchedulerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateInferenceSchedulerInputBuilder {
    pub(crate) model_name: ::std::option::Option<::std::string::String>,
    pub(crate) inference_scheduler_name: ::std::option::Option<::std::string::String>,
    pub(crate) data_delay_offset_in_minutes: ::std::option::Option<i64>,
    pub(crate) data_upload_frequency: ::std::option::Option<crate::types::DataUploadFrequency>,
    pub(crate) data_input_configuration: ::std::option::Option<crate::types::InferenceInputConfiguration>,
    pub(crate) data_output_configuration: ::std::option::Option<crate::types::InferenceOutputConfiguration>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) server_side_kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateInferenceSchedulerInputBuilder {
    /// <p>The name of the previously trained machine learning model being used to create the inference scheduler.</p>
    /// This field is required.
    pub fn model_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the previously trained machine learning model being used to create the inference scheduler.</p>
    pub fn set_model_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_name = input;
        self
    }
    /// <p>The name of the previously trained machine learning model being used to create the inference scheduler.</p>
    pub fn get_model_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_name
    }
    /// <p>The name of the inference scheduler being created.</p>
    /// This field is required.
    pub fn inference_scheduler_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inference_scheduler_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the inference scheduler being created.</p>
    pub fn set_inference_scheduler_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inference_scheduler_name = input;
        self
    }
    /// <p>The name of the inference scheduler being created.</p>
    pub fn get_inference_scheduler_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.inference_scheduler_name
    }
    /// <p>The interval (in minutes) of planned delay at the start of each inference segment. For example, if inference is set to run every ten minutes, the delay is set to five minutes and the time is 09:08. The inference scheduler will wake up at the configured interval (which, without a delay configured, would be 09:10) plus the additional five minute delay time (so 09:15) to check your Amazon S3 bucket. The delay provides a buffer for you to upload data at the same frequency, so that you don't have to stop and restart the scheduler when uploading new data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    pub fn data_delay_offset_in_minutes(mut self, input: i64) -> Self {
        self.data_delay_offset_in_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The interval (in minutes) of planned delay at the start of each inference segment. For example, if inference is set to run every ten minutes, the delay is set to five minutes and the time is 09:08. The inference scheduler will wake up at the configured interval (which, without a delay configured, would be 09:10) plus the additional five minute delay time (so 09:15) to check your Amazon S3 bucket. The delay provides a buffer for you to upload data at the same frequency, so that you don't have to stop and restart the scheduler when uploading new data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    pub fn set_data_delay_offset_in_minutes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.data_delay_offset_in_minutes = input;
        self
    }
    /// <p>The interval (in minutes) of planned delay at the start of each inference segment. For example, if inference is set to run every ten minutes, the delay is set to five minutes and the time is 09:08. The inference scheduler will wake up at the configured interval (which, without a delay configured, would be 09:10) plus the additional five minute delay time (so 09:15) to check your Amazon S3 bucket. The delay provides a buffer for you to upload data at the same frequency, so that you don't have to stop and restart the scheduler when uploading new data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    pub fn get_data_delay_offset_in_minutes(&self) -> &::std::option::Option<i64> {
        &self.data_delay_offset_in_minutes
    }
    /// <p>How often data is uploaded to the source Amazon S3 bucket for the input data. The value chosen is the length of time between data uploads. For instance, if you select 5 minutes, Amazon Lookout for Equipment will upload the real-time data to the source bucket once every 5 minutes. This frequency also determines how often Amazon Lookout for Equipment runs inference on your data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    /// This field is required.
    pub fn data_upload_frequency(mut self, input: crate::types::DataUploadFrequency) -> Self {
        self.data_upload_frequency = ::std::option::Option::Some(input);
        self
    }
    /// <p>How often data is uploaded to the source Amazon S3 bucket for the input data. The value chosen is the length of time between data uploads. For instance, if you select 5 minutes, Amazon Lookout for Equipment will upload the real-time data to the source bucket once every 5 minutes. This frequency also determines how often Amazon Lookout for Equipment runs inference on your data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    pub fn set_data_upload_frequency(mut self, input: ::std::option::Option<crate::types::DataUploadFrequency>) -> Self {
        self.data_upload_frequency = input;
        self
    }
    /// <p>How often data is uploaded to the source Amazon S3 bucket for the input data. The value chosen is the length of time between data uploads. For instance, if you select 5 minutes, Amazon Lookout for Equipment will upload the real-time data to the source bucket once every 5 minutes. This frequency also determines how often Amazon Lookout for Equipment runs inference on your data.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/lookout-for-equipment/latest/ug/understanding-inference-process.html">Understanding the inference process</a>.</p>
    pub fn get_data_upload_frequency(&self) -> &::std::option::Option<crate::types::DataUploadFrequency> {
        &self.data_upload_frequency
    }
    /// <p>Specifies configuration information for the input data for the inference scheduler, including delimiter, format, and dataset location.</p>
    /// This field is required.
    pub fn data_input_configuration(mut self, input: crate::types::InferenceInputConfiguration) -> Self {
        self.data_input_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies configuration information for the input data for the inference scheduler, including delimiter, format, and dataset location.</p>
    pub fn set_data_input_configuration(mut self, input: ::std::option::Option<crate::types::InferenceInputConfiguration>) -> Self {
        self.data_input_configuration = input;
        self
    }
    /// <p>Specifies configuration information for the input data for the inference scheduler, including delimiter, format, and dataset location.</p>
    pub fn get_data_input_configuration(&self) -> &::std::option::Option<crate::types::InferenceInputConfiguration> {
        &self.data_input_configuration
    }
    /// <p>Specifies configuration information for the output results for the inference scheduler, including the S3 location for the output.</p>
    /// This field is required.
    pub fn data_output_configuration(mut self, input: crate::types::InferenceOutputConfiguration) -> Self {
        self.data_output_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies configuration information for the output results for the inference scheduler, including the S3 location for the output.</p>
    pub fn set_data_output_configuration(mut self, input: ::std::option::Option<crate::types::InferenceOutputConfiguration>) -> Self {
        self.data_output_configuration = input;
        self
    }
    /// <p>Specifies configuration information for the output results for the inference scheduler, including the S3 location for the output.</p>
    pub fn get_data_output_configuration(&self) -> &::std::option::Option<crate::types::InferenceOutputConfiguration> {
        &self.data_output_configuration
    }
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source being used for the inference.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source being used for the inference.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source being used for the inference.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>Provides the identifier of the KMS key used to encrypt inference scheduler data by Amazon Lookout for Equipment.</p>
    pub fn server_side_kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_side_kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides the identifier of the KMS key used to encrypt inference scheduler data by Amazon Lookout for Equipment.</p>
    pub fn set_server_side_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_side_kms_key_id = input;
        self
    }
    /// <p>Provides the identifier of the KMS key used to encrypt inference scheduler data by Amazon Lookout for Equipment.</p>
    pub fn get_server_side_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_side_kms_key_id
    }
    /// <p>A unique identifier for the request. If you do not set the client request token, Amazon Lookout for Equipment generates one.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for the request. If you do not set the client request token, Amazon Lookout for Equipment generates one.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique identifier for the request. If you do not set the client request token, Amazon Lookout for Equipment generates one.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Any tags associated with the inference scheduler.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Any tags associated with the inference scheduler.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Any tags associated with the inference scheduler.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateInferenceSchedulerInput`](crate::operation::create_inference_scheduler::CreateInferenceSchedulerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_inference_scheduler::CreateInferenceSchedulerInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_inference_scheduler::CreateInferenceSchedulerInput {
            model_name: self.model_name,
            inference_scheduler_name: self.inference_scheduler_name,
            data_delay_offset_in_minutes: self.data_delay_offset_in_minutes,
            data_upload_frequency: self.data_upload_frequency,
            data_input_configuration: self.data_input_configuration,
            data_output_configuration: self.data_output_configuration,
            role_arn: self.role_arn,
            server_side_kms_key_id: self.server_side_kms_key_id,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
