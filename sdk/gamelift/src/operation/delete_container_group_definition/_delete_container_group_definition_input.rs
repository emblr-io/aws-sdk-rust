// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteContainerGroupDefinitionInput {
    /// <p>The unique identifier for the container group definition to delete. You can use either the <code>Name</code> or <code>ARN</code> value.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The specific version to delete.</p>
    pub version_number: ::std::option::Option<i32>,
    /// <p>The number of most recent versions to keep while deleting all older versions.</p>
    pub version_count_to_retain: ::std::option::Option<i32>,
}
impl DeleteContainerGroupDefinitionInput {
    /// <p>The unique identifier for the container group definition to delete. You can use either the <code>Name</code> or <code>ARN</code> value.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The specific version to delete.</p>
    pub fn version_number(&self) -> ::std::option::Option<i32> {
        self.version_number
    }
    /// <p>The number of most recent versions to keep while deleting all older versions.</p>
    pub fn version_count_to_retain(&self) -> ::std::option::Option<i32> {
        self.version_count_to_retain
    }
}
impl DeleteContainerGroupDefinitionInput {
    /// Creates a new builder-style object to manufacture [`DeleteContainerGroupDefinitionInput`](crate::operation::delete_container_group_definition::DeleteContainerGroupDefinitionInput).
    pub fn builder() -> crate::operation::delete_container_group_definition::builders::DeleteContainerGroupDefinitionInputBuilder {
        crate::operation::delete_container_group_definition::builders::DeleteContainerGroupDefinitionInputBuilder::default()
    }
}

/// A builder for [`DeleteContainerGroupDefinitionInput`](crate::operation::delete_container_group_definition::DeleteContainerGroupDefinitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteContainerGroupDefinitionInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) version_number: ::std::option::Option<i32>,
    pub(crate) version_count_to_retain: ::std::option::Option<i32>,
}
impl DeleteContainerGroupDefinitionInputBuilder {
    /// <p>The unique identifier for the container group definition to delete. You can use either the <code>Name</code> or <code>ARN</code> value.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the container group definition to delete. You can use either the <code>Name</code> or <code>ARN</code> value.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The unique identifier for the container group definition to delete. You can use either the <code>Name</code> or <code>ARN</code> value.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The specific version to delete.</p>
    pub fn version_number(mut self, input: i32) -> Self {
        self.version_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The specific version to delete.</p>
    pub fn set_version_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.version_number = input;
        self
    }
    /// <p>The specific version to delete.</p>
    pub fn get_version_number(&self) -> &::std::option::Option<i32> {
        &self.version_number
    }
    /// <p>The number of most recent versions to keep while deleting all older versions.</p>
    pub fn version_count_to_retain(mut self, input: i32) -> Self {
        self.version_count_to_retain = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of most recent versions to keep while deleting all older versions.</p>
    pub fn set_version_count_to_retain(mut self, input: ::std::option::Option<i32>) -> Self {
        self.version_count_to_retain = input;
        self
    }
    /// <p>The number of most recent versions to keep while deleting all older versions.</p>
    pub fn get_version_count_to_retain(&self) -> &::std::option::Option<i32> {
        &self.version_count_to_retain
    }
    /// Consumes the builder and constructs a [`DeleteContainerGroupDefinitionInput`](crate::operation::delete_container_group_definition::DeleteContainerGroupDefinitionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_container_group_definition::DeleteContainerGroupDefinitionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_container_group_definition::DeleteContainerGroupDefinitionInput {
            name: self.name,
            version_number: self.version_number,
            version_count_to_retain: self.version_count_to_retain,
        })
    }
}
