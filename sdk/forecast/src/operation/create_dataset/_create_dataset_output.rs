// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDatasetOutput {
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub dataset_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateDatasetOutput {
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub fn dataset_arn(&self) -> ::std::option::Option<&str> {
        self.dataset_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateDatasetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateDatasetOutput {
    /// Creates a new builder-style object to manufacture [`CreateDatasetOutput`](crate::operation::create_dataset::CreateDatasetOutput).
    pub fn builder() -> crate::operation::create_dataset::builders::CreateDatasetOutputBuilder {
        crate::operation::create_dataset::builders::CreateDatasetOutputBuilder::default()
    }
}

/// A builder for [`CreateDatasetOutput`](crate::operation::create_dataset::CreateDatasetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDatasetOutputBuilder {
    pub(crate) dataset_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateDatasetOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub fn dataset_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub fn set_dataset_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset.</p>
    pub fn get_dataset_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateDatasetOutput`](crate::operation::create_dataset::CreateDatasetOutput).
    pub fn build(self) -> crate::operation::create_dataset::CreateDatasetOutput {
        crate::operation::create_dataset::CreateDatasetOutput {
            dataset_arn: self.dataset_arn,
            _request_id: self._request_id,
        }
    }
}
