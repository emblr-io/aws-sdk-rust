// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAppInput {
    /// <p>The ID of the application.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
    /// <p>The new name of the application.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The new description of the application.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The name of the service role in the customer's account used by Server Migration Service.</p>
    pub role_name: ::std::option::Option<::std::string::String>,
    /// <p>The server groups in the application to update.</p>
    pub server_groups: ::std::option::Option<::std::vec::Vec<crate::types::ServerGroup>>,
    /// <p>The tags to associate with the application.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl UpdateAppInput {
    /// <p>The ID of the application.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
    /// <p>The new name of the application.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The new description of the application.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The name of the service role in the customer's account used by Server Migration Service.</p>
    pub fn role_name(&self) -> ::std::option::Option<&str> {
        self.role_name.as_deref()
    }
    /// <p>The server groups in the application to update.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.server_groups.is_none()`.
    pub fn server_groups(&self) -> &[crate::types::ServerGroup] {
        self.server_groups.as_deref().unwrap_or_default()
    }
    /// <p>The tags to associate with the application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl UpdateAppInput {
    /// Creates a new builder-style object to manufacture [`UpdateAppInput`](crate::operation::update_app::UpdateAppInput).
    pub fn builder() -> crate::operation::update_app::builders::UpdateAppInputBuilder {
        crate::operation::update_app::builders::UpdateAppInputBuilder::default()
    }
}

/// A builder for [`UpdateAppInput`](crate::operation::update_app::UpdateAppInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAppInputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) role_name: ::std::option::Option<::std::string::String>,
    pub(crate) server_groups: ::std::option::Option<::std::vec::Vec<crate::types::ServerGroup>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl UpdateAppInputBuilder {
    /// <p>The ID of the application.</p>
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the application.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The ID of the application.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The new name of the application.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new name of the application.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The new name of the application.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The new description of the application.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new description of the application.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The new description of the application.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The name of the service role in the customer's account used by Server Migration Service.</p>
    pub fn role_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service role in the customer's account used by Server Migration Service.</p>
    pub fn set_role_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_name = input;
        self
    }
    /// <p>The name of the service role in the customer's account used by Server Migration Service.</p>
    pub fn get_role_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_name
    }
    /// Appends an item to `server_groups`.
    ///
    /// To override the contents of this collection use [`set_server_groups`](Self::set_server_groups).
    ///
    /// <p>The server groups in the application to update.</p>
    pub fn server_groups(mut self, input: crate::types::ServerGroup) -> Self {
        let mut v = self.server_groups.unwrap_or_default();
        v.push(input);
        self.server_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The server groups in the application to update.</p>
    pub fn set_server_groups(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServerGroup>>) -> Self {
        self.server_groups = input;
        self
    }
    /// <p>The server groups in the application to update.</p>
    pub fn get_server_groups(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServerGroup>> {
        &self.server_groups
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to associate with the application.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to associate with the application.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to associate with the application.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`UpdateAppInput`](crate::operation::update_app::UpdateAppInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::update_app::UpdateAppInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_app::UpdateAppInput {
            app_id: self.app_id,
            name: self.name,
            description: self.description,
            role_name: self.role_name,
            server_groups: self.server_groups,
            tags: self.tags,
        })
    }
}
