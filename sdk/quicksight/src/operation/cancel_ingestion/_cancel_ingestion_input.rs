// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelIngestionInput {
    /// <p>The Amazon Web Services account ID.</p>
    pub aws_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the dataset used in the ingestion.</p>
    pub data_set_id: ::std::option::Option<::std::string::String>,
    /// <p>An ID for the ingestion.</p>
    pub ingestion_id: ::std::option::Option<::std::string::String>,
}
impl CancelIngestionInput {
    /// <p>The Amazon Web Services account ID.</p>
    pub fn aws_account_id(&self) -> ::std::option::Option<&str> {
        self.aws_account_id.as_deref()
    }
    /// <p>The ID of the dataset used in the ingestion.</p>
    pub fn data_set_id(&self) -> ::std::option::Option<&str> {
        self.data_set_id.as_deref()
    }
    /// <p>An ID for the ingestion.</p>
    pub fn ingestion_id(&self) -> ::std::option::Option<&str> {
        self.ingestion_id.as_deref()
    }
}
impl CancelIngestionInput {
    /// Creates a new builder-style object to manufacture [`CancelIngestionInput`](crate::operation::cancel_ingestion::CancelIngestionInput).
    pub fn builder() -> crate::operation::cancel_ingestion::builders::CancelIngestionInputBuilder {
        crate::operation::cancel_ingestion::builders::CancelIngestionInputBuilder::default()
    }
}

/// A builder for [`CancelIngestionInput`](crate::operation::cancel_ingestion::CancelIngestionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelIngestionInputBuilder {
    pub(crate) aws_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) data_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) ingestion_id: ::std::option::Option<::std::string::String>,
}
impl CancelIngestionInputBuilder {
    /// <p>The Amazon Web Services account ID.</p>
    /// This field is required.
    pub fn aws_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn set_aws_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn get_aws_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_account_id
    }
    /// <p>The ID of the dataset used in the ingestion.</p>
    /// This field is required.
    pub fn data_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the dataset used in the ingestion.</p>
    pub fn set_data_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_set_id = input;
        self
    }
    /// <p>The ID of the dataset used in the ingestion.</p>
    pub fn get_data_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_set_id
    }
    /// <p>An ID for the ingestion.</p>
    /// This field is required.
    pub fn ingestion_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ingestion_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An ID for the ingestion.</p>
    pub fn set_ingestion_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ingestion_id = input;
        self
    }
    /// <p>An ID for the ingestion.</p>
    pub fn get_ingestion_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ingestion_id
    }
    /// Consumes the builder and constructs a [`CancelIngestionInput`](crate::operation::cancel_ingestion::CancelIngestionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_ingestion::CancelIngestionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::cancel_ingestion::CancelIngestionInput {
            aws_account_id: self.aws_account_id,
            data_set_id: self.data_set_id,
            ingestion_id: self.ingestion_id,
        })
    }
}
