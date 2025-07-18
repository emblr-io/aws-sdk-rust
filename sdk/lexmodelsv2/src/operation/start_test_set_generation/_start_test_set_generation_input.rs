// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartTestSetGenerationInput {
    /// <p>The test set name for the test set generation request.</p>
    pub test_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The test set description for the test set generation request.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon S3 storage location for the test set generation.</p>
    pub storage_location: ::std::option::Option<crate::types::TestSetStorageLocation>,
    /// <p>The data source for the test set generation.</p>
    pub generation_data_source: ::std::option::Option<crate::types::TestSetGenerationDataSource>,
    /// <p>The roleARN used for any operation in the test set to access resources in the Amazon Web Services account.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>A list of tags to add to the test set. You can only add tags when you import/generate a new test set. You can't use the <code>UpdateTestSet</code> operation to update tags. To update tags, use the <code>TagResource</code> operation.</p>
    pub test_set_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl StartTestSetGenerationInput {
    /// <p>The test set name for the test set generation request.</p>
    pub fn test_set_name(&self) -> ::std::option::Option<&str> {
        self.test_set_name.as_deref()
    }
    /// <p>The test set description for the test set generation request.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The Amazon S3 storage location for the test set generation.</p>
    pub fn storage_location(&self) -> ::std::option::Option<&crate::types::TestSetStorageLocation> {
        self.storage_location.as_ref()
    }
    /// <p>The data source for the test set generation.</p>
    pub fn generation_data_source(&self) -> ::std::option::Option<&crate::types::TestSetGenerationDataSource> {
        self.generation_data_source.as_ref()
    }
    /// <p>The roleARN used for any operation in the test set to access resources in the Amazon Web Services account.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>A list of tags to add to the test set. You can only add tags when you import/generate a new test set. You can't use the <code>UpdateTestSet</code> operation to update tags. To update tags, use the <code>TagResource</code> operation.</p>
    pub fn test_set_tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.test_set_tags.as_ref()
    }
}
impl StartTestSetGenerationInput {
    /// Creates a new builder-style object to manufacture [`StartTestSetGenerationInput`](crate::operation::start_test_set_generation::StartTestSetGenerationInput).
    pub fn builder() -> crate::operation::start_test_set_generation::builders::StartTestSetGenerationInputBuilder {
        crate::operation::start_test_set_generation::builders::StartTestSetGenerationInputBuilder::default()
    }
}

/// A builder for [`StartTestSetGenerationInput`](crate::operation::start_test_set_generation::StartTestSetGenerationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartTestSetGenerationInputBuilder {
    pub(crate) test_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) storage_location: ::std::option::Option<crate::types::TestSetStorageLocation>,
    pub(crate) generation_data_source: ::std::option::Option<crate::types::TestSetGenerationDataSource>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) test_set_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl StartTestSetGenerationInputBuilder {
    /// <p>The test set name for the test set generation request.</p>
    /// This field is required.
    pub fn test_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test set name for the test set generation request.</p>
    pub fn set_test_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_set_name = input;
        self
    }
    /// <p>The test set name for the test set generation request.</p>
    pub fn get_test_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_set_name
    }
    /// <p>The test set description for the test set generation request.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The test set description for the test set generation request.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The test set description for the test set generation request.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The Amazon S3 storage location for the test set generation.</p>
    /// This field is required.
    pub fn storage_location(mut self, input: crate::types::TestSetStorageLocation) -> Self {
        self.storage_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon S3 storage location for the test set generation.</p>
    pub fn set_storage_location(mut self, input: ::std::option::Option<crate::types::TestSetStorageLocation>) -> Self {
        self.storage_location = input;
        self
    }
    /// <p>The Amazon S3 storage location for the test set generation.</p>
    pub fn get_storage_location(&self) -> &::std::option::Option<crate::types::TestSetStorageLocation> {
        &self.storage_location
    }
    /// <p>The data source for the test set generation.</p>
    /// This field is required.
    pub fn generation_data_source(mut self, input: crate::types::TestSetGenerationDataSource) -> Self {
        self.generation_data_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The data source for the test set generation.</p>
    pub fn set_generation_data_source(mut self, input: ::std::option::Option<crate::types::TestSetGenerationDataSource>) -> Self {
        self.generation_data_source = input;
        self
    }
    /// <p>The data source for the test set generation.</p>
    pub fn get_generation_data_source(&self) -> &::std::option::Option<crate::types::TestSetGenerationDataSource> {
        &self.generation_data_source
    }
    /// <p>The roleARN used for any operation in the test set to access resources in the Amazon Web Services account.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The roleARN used for any operation in the test set to access resources in the Amazon Web Services account.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The roleARN used for any operation in the test set to access resources in the Amazon Web Services account.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Adds a key-value pair to `test_set_tags`.
    ///
    /// To override the contents of this collection use [`set_test_set_tags`](Self::set_test_set_tags).
    ///
    /// <p>A list of tags to add to the test set. You can only add tags when you import/generate a new test set. You can't use the <code>UpdateTestSet</code> operation to update tags. To update tags, use the <code>TagResource</code> operation.</p>
    pub fn test_set_tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.test_set_tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.test_set_tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of tags to add to the test set. You can only add tags when you import/generate a new test set. You can't use the <code>UpdateTestSet</code> operation to update tags. To update tags, use the <code>TagResource</code> operation.</p>
    pub fn set_test_set_tags(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.test_set_tags = input;
        self
    }
    /// <p>A list of tags to add to the test set. You can only add tags when you import/generate a new test set. You can't use the <code>UpdateTestSet</code> operation to update tags. To update tags, use the <code>TagResource</code> operation.</p>
    pub fn get_test_set_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.test_set_tags
    }
    /// Consumes the builder and constructs a [`StartTestSetGenerationInput`](crate::operation::start_test_set_generation::StartTestSetGenerationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::start_test_set_generation::StartTestSetGenerationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::start_test_set_generation::StartTestSetGenerationInput {
            test_set_name: self.test_set_name,
            description: self.description,
            storage_location: self.storage_location,
            generation_data_source: self.generation_data_source,
            role_arn: self.role_arn,
            test_set_tags: self.test_set_tags,
        })
    }
}
