// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetGroupInput {
    /// <p>The identifier of the application id the group is attached to.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the index the group is attached to.</p>
    pub index_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the group.</p>
    pub group_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the data source the group is attached to.</p>
    pub data_source_id: ::std::option::Option<::std::string::String>,
}
impl GetGroupInput {
    /// <p>The identifier of the application id the group is attached to.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>The identifier of the index the group is attached to.</p>
    pub fn index_id(&self) -> ::std::option::Option<&str> {
        self.index_id.as_deref()
    }
    /// <p>The name of the group.</p>
    pub fn group_name(&self) -> ::std::option::Option<&str> {
        self.group_name.as_deref()
    }
    /// <p>The identifier of the data source the group is attached to.</p>
    pub fn data_source_id(&self) -> ::std::option::Option<&str> {
        self.data_source_id.as_deref()
    }
}
impl GetGroupInput {
    /// Creates a new builder-style object to manufacture [`GetGroupInput`](crate::operation::get_group::GetGroupInput).
    pub fn builder() -> crate::operation::get_group::builders::GetGroupInputBuilder {
        crate::operation::get_group::builders::GetGroupInputBuilder::default()
    }
}

/// A builder for [`GetGroupInput`](crate::operation::get_group::GetGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetGroupInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) index_id: ::std::option::Option<::std::string::String>,
    pub(crate) group_name: ::std::option::Option<::std::string::String>,
    pub(crate) data_source_id: ::std::option::Option<::std::string::String>,
}
impl GetGroupInputBuilder {
    /// <p>The identifier of the application id the group is attached to.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the application id the group is attached to.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The identifier of the application id the group is attached to.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// <p>The identifier of the index the group is attached to.</p>
    /// This field is required.
    pub fn index_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the index the group is attached to.</p>
    pub fn set_index_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_id = input;
        self
    }
    /// <p>The identifier of the index the group is attached to.</p>
    pub fn get_index_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_id
    }
    /// <p>The name of the group.</p>
    /// This field is required.
    pub fn group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the group.</p>
    pub fn set_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_name = input;
        self
    }
    /// <p>The name of the group.</p>
    pub fn get_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_name
    }
    /// <p>The identifier of the data source the group is attached to.</p>
    pub fn data_source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the data source the group is attached to.</p>
    pub fn set_data_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source_id = input;
        self
    }
    /// <p>The identifier of the data source the group is attached to.</p>
    pub fn get_data_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source_id
    }
    /// Consumes the builder and constructs a [`GetGroupInput`](crate::operation::get_group::GetGroupInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_group::GetGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_group::GetGroupInput {
            application_id: self.application_id,
            index_id: self.index_id,
            group_name: self.group_name,
            data_source_id: self.data_source_id,
        })
    }
}
