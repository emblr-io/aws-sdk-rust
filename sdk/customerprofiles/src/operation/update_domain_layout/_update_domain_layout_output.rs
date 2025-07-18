// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateDomainLayoutOutput {
    /// <p>The unique name of the layout.</p>
    pub layout_definition_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the layout</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The display name of the layout</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>If set to true for a layout, this layout will be used by default to view data. If set to false, then the layout will not be used by default, but it can be used to view data by explicitly selecting it in the console.</p>
    pub is_default: bool,
    /// <p>The type of layout that can be used to view data under a Customer Profiles domain.</p>
    pub layout_type: ::std::option::Option<crate::types::LayoutType>,
    /// <p>A customizable layout that can be used to view data under a Customer Profiles domain.</p>
    pub layout: ::std::option::Option<::std::string::String>,
    /// <p>The version used to create layout.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp of when the layout was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The timestamp of when the layout was most recently updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateDomainLayoutOutput {
    /// <p>The unique name of the layout.</p>
    pub fn layout_definition_name(&self) -> ::std::option::Option<&str> {
        self.layout_definition_name.as_deref()
    }
    /// <p>The description of the layout</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The display name of the layout</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>If set to true for a layout, this layout will be used by default to view data. If set to false, then the layout will not be used by default, but it can be used to view data by explicitly selecting it in the console.</p>
    pub fn is_default(&self) -> bool {
        self.is_default
    }
    /// <p>The type of layout that can be used to view data under a Customer Profiles domain.</p>
    pub fn layout_type(&self) -> ::std::option::Option<&crate::types::LayoutType> {
        self.layout_type.as_ref()
    }
    /// <p>A customizable layout that can be used to view data under a Customer Profiles domain.</p>
    pub fn layout(&self) -> ::std::option::Option<&str> {
        self.layout.as_deref()
    }
    /// <p>The version used to create layout.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The timestamp of when the layout was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The timestamp of when the layout was most recently updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::std::fmt::Debug for UpdateDomainLayoutOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateDomainLayoutOutput");
        formatter.field("layout_definition_name", &self.layout_definition_name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("display_name", &self.display_name);
        formatter.field("is_default", &self.is_default);
        formatter.field("layout_type", &self.layout_type);
        formatter.field("layout", &"*** Sensitive Data Redacted ***");
        formatter.field("version", &self.version);
        formatter.field("created_at", &self.created_at);
        formatter.field("last_updated_at", &self.last_updated_at);
        formatter.field("tags", &self.tags);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for UpdateDomainLayoutOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateDomainLayoutOutput {
    /// Creates a new builder-style object to manufacture [`UpdateDomainLayoutOutput`](crate::operation::update_domain_layout::UpdateDomainLayoutOutput).
    pub fn builder() -> crate::operation::update_domain_layout::builders::UpdateDomainLayoutOutputBuilder {
        crate::operation::update_domain_layout::builders::UpdateDomainLayoutOutputBuilder::default()
    }
}

/// A builder for [`UpdateDomainLayoutOutput`](crate::operation::update_domain_layout::UpdateDomainLayoutOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateDomainLayoutOutputBuilder {
    pub(crate) layout_definition_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) is_default: ::std::option::Option<bool>,
    pub(crate) layout_type: ::std::option::Option<crate::types::LayoutType>,
    pub(crate) layout: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl UpdateDomainLayoutOutputBuilder {
    /// <p>The unique name of the layout.</p>
    pub fn layout_definition_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.layout_definition_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique name of the layout.</p>
    pub fn set_layout_definition_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.layout_definition_name = input;
        self
    }
    /// <p>The unique name of the layout.</p>
    pub fn get_layout_definition_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.layout_definition_name
    }
    /// <p>The description of the layout</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the layout</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the layout</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The display name of the layout</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the layout</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The display name of the layout</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// <p>If set to true for a layout, this layout will be used by default to view data. If set to false, then the layout will not be used by default, but it can be used to view data by explicitly selecting it in the console.</p>
    pub fn is_default(mut self, input: bool) -> Self {
        self.is_default = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to true for a layout, this layout will be used by default to view data. If set to false, then the layout will not be used by default, but it can be used to view data by explicitly selecting it in the console.</p>
    pub fn set_is_default(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_default = input;
        self
    }
    /// <p>If set to true for a layout, this layout will be used by default to view data. If set to false, then the layout will not be used by default, but it can be used to view data by explicitly selecting it in the console.</p>
    pub fn get_is_default(&self) -> &::std::option::Option<bool> {
        &self.is_default
    }
    /// <p>The type of layout that can be used to view data under a Customer Profiles domain.</p>
    pub fn layout_type(mut self, input: crate::types::LayoutType) -> Self {
        self.layout_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of layout that can be used to view data under a Customer Profiles domain.</p>
    pub fn set_layout_type(mut self, input: ::std::option::Option<crate::types::LayoutType>) -> Self {
        self.layout_type = input;
        self
    }
    /// <p>The type of layout that can be used to view data under a Customer Profiles domain.</p>
    pub fn get_layout_type(&self) -> &::std::option::Option<crate::types::LayoutType> {
        &self.layout_type
    }
    /// <p>A customizable layout that can be used to view data under a Customer Profiles domain.</p>
    pub fn layout(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.layout = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A customizable layout that can be used to view data under a Customer Profiles domain.</p>
    pub fn set_layout(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.layout = input;
        self
    }
    /// <p>A customizable layout that can be used to view data under a Customer Profiles domain.</p>
    pub fn get_layout(&self) -> &::std::option::Option<::std::string::String> {
        &self.layout
    }
    /// <p>The version used to create layout.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version used to create layout.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version used to create layout.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The timestamp of when the layout was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the layout was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The timestamp of when the layout was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The timestamp of when the layout was most recently updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp of when the layout was most recently updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The timestamp of when the layout was most recently updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
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
    /// Consumes the builder and constructs a [`UpdateDomainLayoutOutput`](crate::operation::update_domain_layout::UpdateDomainLayoutOutput).
    pub fn build(self) -> crate::operation::update_domain_layout::UpdateDomainLayoutOutput {
        crate::operation::update_domain_layout::UpdateDomainLayoutOutput {
            layout_definition_name: self.layout_definition_name,
            description: self.description,
            display_name: self.display_name,
            is_default: self.is_default.unwrap_or_default(),
            layout_type: self.layout_type,
            layout: self.layout,
            version: self.version,
            created_at: self.created_at,
            last_updated_at: self.last_updated_at,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for UpdateDomainLayoutOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateDomainLayoutOutputBuilder");
        formatter.field("layout_definition_name", &self.layout_definition_name);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("display_name", &self.display_name);
        formatter.field("is_default", &self.is_default);
        formatter.field("layout_type", &self.layout_type);
        formatter.field("layout", &"*** Sensitive Data Redacted ***");
        formatter.field("version", &self.version);
        formatter.field("created_at", &self.created_at);
        formatter.field("last_updated_at", &self.last_updated_at);
        formatter.field("tags", &self.tags);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
