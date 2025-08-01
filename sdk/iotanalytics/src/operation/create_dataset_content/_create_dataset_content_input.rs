// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDatasetContentInput {
    /// <p>The name of the dataset.</p>
    pub dataset_name: ::std::option::Option<::std::string::String>,
    /// <p>The version ID of the dataset content. To specify <code>versionId</code> for a dataset content, the dataset must use a <a href="https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html">DeltaTimer</a> filter.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
}
impl CreateDatasetContentInput {
    /// <p>The name of the dataset.</p>
    pub fn dataset_name(&self) -> ::std::option::Option<&str> {
        self.dataset_name.as_deref()
    }
    /// <p>The version ID of the dataset content. To specify <code>versionId</code> for a dataset content, the dataset must use a <a href="https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html">DeltaTimer</a> filter.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
}
impl CreateDatasetContentInput {
    /// Creates a new builder-style object to manufacture [`CreateDatasetContentInput`](crate::operation::create_dataset_content::CreateDatasetContentInput).
    pub fn builder() -> crate::operation::create_dataset_content::builders::CreateDatasetContentInputBuilder {
        crate::operation::create_dataset_content::builders::CreateDatasetContentInputBuilder::default()
    }
}

/// A builder for [`CreateDatasetContentInput`](crate::operation::create_dataset_content::CreateDatasetContentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDatasetContentInputBuilder {
    pub(crate) dataset_name: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
}
impl CreateDatasetContentInputBuilder {
    /// <p>The name of the dataset.</p>
    /// This field is required.
    pub fn dataset_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the dataset.</p>
    pub fn set_dataset_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_name = input;
        self
    }
    /// <p>The name of the dataset.</p>
    pub fn get_dataset_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_name
    }
    /// <p>The version ID of the dataset content. To specify <code>versionId</code> for a dataset content, the dataset must use a <a href="https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html">DeltaTimer</a> filter.</p>
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version ID of the dataset content. To specify <code>versionId</code> for a dataset content, the dataset must use a <a href="https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html">DeltaTimer</a> filter.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>The version ID of the dataset content. To specify <code>versionId</code> for a dataset content, the dataset must use a <a href="https://docs.aws.amazon.com/iotanalytics/latest/APIReference/API_DeltaTime.html">DeltaTimer</a> filter.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// Consumes the builder and constructs a [`CreateDatasetContentInput`](crate::operation::create_dataset_content::CreateDatasetContentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_dataset_content::CreateDatasetContentInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_dataset_content::CreateDatasetContentInput {
            dataset_name: self.dataset_name,
            version_id: self.version_id,
        })
    }
}
