// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartDataIngestionJobInput {
    /// <p>The name of the dataset being used by the data ingestion job.</p>
    pub dataset_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies information for the input data for the data ingestion job, including dataset S3 location.</p>
    pub ingestion_input_configuration: ::std::option::Option<crate::types::IngestionInputConfiguration>,
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source for the data ingestion job.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier for the request. If you do not set the client request token, Amazon Lookout for Equipment generates one.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl StartDataIngestionJobInput {
    /// <p>The name of the dataset being used by the data ingestion job.</p>
    pub fn dataset_name(&self) -> ::std::option::Option<&str> {
        self.dataset_name.as_deref()
    }
    /// <p>Specifies information for the input data for the data ingestion job, including dataset S3 location.</p>
    pub fn ingestion_input_configuration(&self) -> ::std::option::Option<&crate::types::IngestionInputConfiguration> {
        self.ingestion_input_configuration.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source for the data ingestion job.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>A unique identifier for the request. If you do not set the client request token, Amazon Lookout for Equipment generates one.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl StartDataIngestionJobInput {
    /// Creates a new builder-style object to manufacture [`StartDataIngestionJobInput`](crate::operation::start_data_ingestion_job::StartDataIngestionJobInput).
    pub fn builder() -> crate::operation::start_data_ingestion_job::builders::StartDataIngestionJobInputBuilder {
        crate::operation::start_data_ingestion_job::builders::StartDataIngestionJobInputBuilder::default()
    }
}

/// A builder for [`StartDataIngestionJobInput`](crate::operation::start_data_ingestion_job::StartDataIngestionJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartDataIngestionJobInputBuilder {
    pub(crate) dataset_name: ::std::option::Option<::std::string::String>,
    pub(crate) ingestion_input_configuration: ::std::option::Option<crate::types::IngestionInputConfiguration>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl StartDataIngestionJobInputBuilder {
    /// <p>The name of the dataset being used by the data ingestion job.</p>
    /// This field is required.
    pub fn dataset_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the dataset being used by the data ingestion job.</p>
    pub fn set_dataset_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_name = input;
        self
    }
    /// <p>The name of the dataset being used by the data ingestion job.</p>
    pub fn get_dataset_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_name
    }
    /// <p>Specifies information for the input data for the data ingestion job, including dataset S3 location.</p>
    /// This field is required.
    pub fn ingestion_input_configuration(mut self, input: crate::types::IngestionInputConfiguration) -> Self {
        self.ingestion_input_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies information for the input data for the data ingestion job, including dataset S3 location.</p>
    pub fn set_ingestion_input_configuration(mut self, input: ::std::option::Option<crate::types::IngestionInputConfiguration>) -> Self {
        self.ingestion_input_configuration = input;
        self
    }
    /// <p>Specifies information for the input data for the data ingestion job, including dataset S3 location.</p>
    pub fn get_ingestion_input_configuration(&self) -> &::std::option::Option<crate::types::IngestionInputConfiguration> {
        &self.ingestion_input_configuration
    }
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source for the data ingestion job.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source for the data ingestion job.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of a role with permission to access the data source for the data ingestion job.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
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
    /// Consumes the builder and constructs a [`StartDataIngestionJobInput`](crate::operation::start_data_ingestion_job::StartDataIngestionJobInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_data_ingestion_job::StartDataIngestionJobInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_data_ingestion_job::StartDataIngestionJobInput {
            dataset_name: self.dataset_name,
            ingestion_input_configuration: self.ingestion_input_configuration,
            role_arn: self.role_arn,
            client_token: self.client_token,
        })
    }
}
