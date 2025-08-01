// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of quick response search.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct QuickResponseSearchResultData {
    /// <p>The Amazon Resource Name (ARN) of the quick response.</p>
    pub quick_response_arn: ::std::string::String,
    /// <p>The identifier of the quick response.</p>
    pub quick_response_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the knowledge base.</p>
    pub knowledge_base_arn: ::std::string::String,
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub knowledge_base_id: ::std::string::String,
    /// <p>The name of the quick response.</p>
    pub name: ::std::string::String,
    /// <p>The media type of the quick response content.</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=plain</code> for quick response written in plain text.</p></li>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=markdown</code> for quick response written in richtext.</p></li>
    /// </ul>
    pub content_type: ::std::string::String,
    /// <p>The resource status of the quick response.</p>
    pub status: crate::types::QuickResponseStatus,
    /// <p>The contents of the quick response.</p>
    pub contents: ::std::option::Option<crate::types::QuickResponseContents>,
    /// <p>The timestamp when the quick response was created.</p>
    pub created_time: ::aws_smithy_types::DateTime,
    /// <p>The timestamp when the quick response search result data was last modified.</p>
    pub last_modified_time: ::aws_smithy_types::DateTime,
    /// <p>Whether the quick response is active.</p>
    pub is_active: bool,
    /// <p>The description of the quick response.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The configuration information of the user groups that the quick response is accessible to.</p>
    pub grouping_configuration: ::std::option::Option<crate::types::GroupingConfiguration>,
    /// <p>The shortcut key of the quick response. The value should be unique across the knowledge base.</p>
    pub shortcut_key: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the quick response search result data.</p>
    pub last_modified_by: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Connect contact channels this quick response applies to. The supported contact channel types include <code>Chat</code>.</p>
    pub channels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The language code value for the language in which the quick response is written.</p>
    pub language: ::std::option::Option<::std::string::String>,
    /// <p>The user defined contact attributes that are not resolved when the search result is returned.</p>
    pub attributes_not_interpolated: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The user defined contact attributes that are resolved when the search result is returned.</p>
    pub attributes_interpolated: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl QuickResponseSearchResultData {
    /// <p>The Amazon Resource Name (ARN) of the quick response.</p>
    pub fn quick_response_arn(&self) -> &str {
        use std::ops::Deref;
        self.quick_response_arn.deref()
    }
    /// <p>The identifier of the quick response.</p>
    pub fn quick_response_id(&self) -> &str {
        use std::ops::Deref;
        self.quick_response_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the knowledge base.</p>
    pub fn knowledge_base_arn(&self) -> &str {
        use std::ops::Deref;
        self.knowledge_base_arn.deref()
    }
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn knowledge_base_id(&self) -> &str {
        use std::ops::Deref;
        self.knowledge_base_id.deref()
    }
    /// <p>The name of the quick response.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The media type of the quick response content.</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=plain</code> for quick response written in plain text.</p></li>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=markdown</code> for quick response written in richtext.</p></li>
    /// </ul>
    pub fn content_type(&self) -> &str {
        use std::ops::Deref;
        self.content_type.deref()
    }
    /// <p>The resource status of the quick response.</p>
    pub fn status(&self) -> &crate::types::QuickResponseStatus {
        &self.status
    }
    /// <p>The contents of the quick response.</p>
    pub fn contents(&self) -> ::std::option::Option<&crate::types::QuickResponseContents> {
        self.contents.as_ref()
    }
    /// <p>The timestamp when the quick response was created.</p>
    pub fn created_time(&self) -> &::aws_smithy_types::DateTime {
        &self.created_time
    }
    /// <p>The timestamp when the quick response search result data was last modified.</p>
    pub fn last_modified_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_modified_time
    }
    /// <p>Whether the quick response is active.</p>
    pub fn is_active(&self) -> bool {
        self.is_active
    }
    /// <p>The description of the quick response.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The configuration information of the user groups that the quick response is accessible to.</p>
    pub fn grouping_configuration(&self) -> ::std::option::Option<&crate::types::GroupingConfiguration> {
        self.grouping_configuration.as_ref()
    }
    /// <p>The shortcut key of the quick response. The value should be unique across the knowledge base.</p>
    pub fn shortcut_key(&self) -> ::std::option::Option<&str> {
        self.shortcut_key.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the quick response search result data.</p>
    pub fn last_modified_by(&self) -> ::std::option::Option<&str> {
        self.last_modified_by.as_deref()
    }
    /// <p>The Amazon Connect contact channels this quick response applies to. The supported contact channel types include <code>Chat</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.channels.is_none()`.
    pub fn channels(&self) -> &[::std::string::String] {
        self.channels.as_deref().unwrap_or_default()
    }
    /// <p>The language code value for the language in which the quick response is written.</p>
    pub fn language(&self) -> ::std::option::Option<&str> {
        self.language.as_deref()
    }
    /// <p>The user defined contact attributes that are not resolved when the search result is returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attributes_not_interpolated.is_none()`.
    pub fn attributes_not_interpolated(&self) -> &[::std::string::String] {
        self.attributes_not_interpolated.as_deref().unwrap_or_default()
    }
    /// <p>The user defined contact attributes that are resolved when the search result is returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attributes_interpolated.is_none()`.
    pub fn attributes_interpolated(&self) -> &[::std::string::String] {
        self.attributes_interpolated.as_deref().unwrap_or_default()
    }
    /// <p>The tags used to organize, track, or control access for this resource.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::std::fmt::Debug for QuickResponseSearchResultData {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("QuickResponseSearchResultData");
        formatter.field("quick_response_arn", &self.quick_response_arn);
        formatter.field("quick_response_id", &self.quick_response_id);
        formatter.field("knowledge_base_arn", &self.knowledge_base_arn);
        formatter.field("knowledge_base_id", &self.knowledge_base_id);
        formatter.field("name", &self.name);
        formatter.field("content_type", &self.content_type);
        formatter.field("status", &self.status);
        formatter.field("contents", &self.contents);
        formatter.field("created_time", &self.created_time);
        formatter.field("last_modified_time", &self.last_modified_time);
        formatter.field("is_active", &self.is_active);
        formatter.field("description", &self.description);
        formatter.field("grouping_configuration", &self.grouping_configuration);
        formatter.field("shortcut_key", &self.shortcut_key);
        formatter.field("last_modified_by", &self.last_modified_by);
        formatter.field("channels", &"*** Sensitive Data Redacted ***");
        formatter.field("language", &self.language);
        formatter.field("attributes_not_interpolated", &"*** Sensitive Data Redacted ***");
        formatter.field("attributes_interpolated", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
impl QuickResponseSearchResultData {
    /// Creates a new builder-style object to manufacture [`QuickResponseSearchResultData`](crate::types::QuickResponseSearchResultData).
    pub fn builder() -> crate::types::builders::QuickResponseSearchResultDataBuilder {
        crate::types::builders::QuickResponseSearchResultDataBuilder::default()
    }
}

/// A builder for [`QuickResponseSearchResultData`](crate::types::QuickResponseSearchResultData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct QuickResponseSearchResultDataBuilder {
    pub(crate) quick_response_arn: ::std::option::Option<::std::string::String>,
    pub(crate) quick_response_id: ::std::option::Option<::std::string::String>,
    pub(crate) knowledge_base_arn: ::std::option::Option<::std::string::String>,
    pub(crate) knowledge_base_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) content_type: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::QuickResponseStatus>,
    pub(crate) contents: ::std::option::Option<crate::types::QuickResponseContents>,
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) is_active: ::std::option::Option<bool>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) grouping_configuration: ::std::option::Option<crate::types::GroupingConfiguration>,
    pub(crate) shortcut_key: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_by: ::std::option::Option<::std::string::String>,
    pub(crate) channels: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) language: ::std::option::Option<::std::string::String>,
    pub(crate) attributes_not_interpolated: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) attributes_interpolated: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl QuickResponseSearchResultDataBuilder {
    /// <p>The Amazon Resource Name (ARN) of the quick response.</p>
    /// This field is required.
    pub fn quick_response_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.quick_response_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the quick response.</p>
    pub fn set_quick_response_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.quick_response_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the quick response.</p>
    pub fn get_quick_response_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.quick_response_arn
    }
    /// <p>The identifier of the quick response.</p>
    /// This field is required.
    pub fn quick_response_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.quick_response_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the quick response.</p>
    pub fn set_quick_response_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.quick_response_id = input;
        self
    }
    /// <p>The identifier of the quick response.</p>
    pub fn get_quick_response_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.quick_response_id
    }
    /// <p>The Amazon Resource Name (ARN) of the knowledge base.</p>
    /// This field is required.
    pub fn knowledge_base_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.knowledge_base_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the knowledge base.</p>
    pub fn set_knowledge_base_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.knowledge_base_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the knowledge base.</p>
    pub fn get_knowledge_base_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.knowledge_base_arn
    }
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    /// This field is required.
    pub fn knowledge_base_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.knowledge_base_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn set_knowledge_base_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.knowledge_base_id = input;
        self
    }
    /// <p>The identifier of the knowledge base. This should not be a QUICK_RESPONSES type knowledge base if you're storing Wisdom Content resource to it. Can be either the ID or the ARN. URLs cannot contain the ARN.</p>
    pub fn get_knowledge_base_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.knowledge_base_id
    }
    /// <p>The name of the quick response.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the quick response.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the quick response.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The media type of the quick response content.</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=plain</code> for quick response written in plain text.</p></li>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=markdown</code> for quick response written in richtext.</p></li>
    /// </ul>
    /// This field is required.
    pub fn content_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.content_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The media type of the quick response content.</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=plain</code> for quick response written in plain text.</p></li>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=markdown</code> for quick response written in richtext.</p></li>
    /// </ul>
    pub fn set_content_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.content_type = input;
        self
    }
    /// <p>The media type of the quick response content.</p>
    /// <ul>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=plain</code> for quick response written in plain text.</p></li>
    /// <li>
    /// <p>Use <code>application/x.quickresponse;format=markdown</code> for quick response written in richtext.</p></li>
    /// </ul>
    pub fn get_content_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.content_type
    }
    /// <p>The resource status of the quick response.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::QuickResponseStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource status of the quick response.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::QuickResponseStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The resource status of the quick response.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::QuickResponseStatus> {
        &self.status
    }
    /// <p>The contents of the quick response.</p>
    /// This field is required.
    pub fn contents(mut self, input: crate::types::QuickResponseContents) -> Self {
        self.contents = ::std::option::Option::Some(input);
        self
    }
    /// <p>The contents of the quick response.</p>
    pub fn set_contents(mut self, input: ::std::option::Option<crate::types::QuickResponseContents>) -> Self {
        self.contents = input;
        self
    }
    /// <p>The contents of the quick response.</p>
    pub fn get_contents(&self) -> &::std::option::Option<crate::types::QuickResponseContents> {
        &self.contents
    }
    /// <p>The timestamp when the quick response was created.</p>
    /// This field is required.
    pub fn created_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the quick response was created.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>The timestamp when the quick response was created.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time
    }
    /// <p>The timestamp when the quick response search result data was last modified.</p>
    /// This field is required.
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp when the quick response search result data was last modified.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The timestamp when the quick response search result data was last modified.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>Whether the quick response is active.</p>
    /// This field is required.
    pub fn is_active(mut self, input: bool) -> Self {
        self.is_active = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the quick response is active.</p>
    pub fn set_is_active(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_active = input;
        self
    }
    /// <p>Whether the quick response is active.</p>
    pub fn get_is_active(&self) -> &::std::option::Option<bool> {
        &self.is_active
    }
    /// <p>The description of the quick response.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the quick response.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the quick response.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The configuration information of the user groups that the quick response is accessible to.</p>
    pub fn grouping_configuration(mut self, input: crate::types::GroupingConfiguration) -> Self {
        self.grouping_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration information of the user groups that the quick response is accessible to.</p>
    pub fn set_grouping_configuration(mut self, input: ::std::option::Option<crate::types::GroupingConfiguration>) -> Self {
        self.grouping_configuration = input;
        self
    }
    /// <p>The configuration information of the user groups that the quick response is accessible to.</p>
    pub fn get_grouping_configuration(&self) -> &::std::option::Option<crate::types::GroupingConfiguration> {
        &self.grouping_configuration
    }
    /// <p>The shortcut key of the quick response. The value should be unique across the knowledge base.</p>
    pub fn shortcut_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.shortcut_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The shortcut key of the quick response. The value should be unique across the knowledge base.</p>
    pub fn set_shortcut_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.shortcut_key = input;
        self
    }
    /// <p>The shortcut key of the quick response. The value should be unique across the knowledge base.</p>
    pub fn get_shortcut_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.shortcut_key
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the quick response search result data.</p>
    pub fn last_modified_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the quick response search result data.</p>
    pub fn set_last_modified_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified_by = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user who last updated the quick response search result data.</p>
    pub fn get_last_modified_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified_by
    }
    /// Appends an item to `channels`.
    ///
    /// To override the contents of this collection use [`set_channels`](Self::set_channels).
    ///
    /// <p>The Amazon Connect contact channels this quick response applies to. The supported contact channel types include <code>Chat</code>.</p>
    pub fn channels(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.channels.unwrap_or_default();
        v.push(input.into());
        self.channels = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Connect contact channels this quick response applies to. The supported contact channel types include <code>Chat</code>.</p>
    pub fn set_channels(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.channels = input;
        self
    }
    /// <p>The Amazon Connect contact channels this quick response applies to. The supported contact channel types include <code>Chat</code>.</p>
    pub fn get_channels(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.channels
    }
    /// <p>The language code value for the language in which the quick response is written.</p>
    pub fn language(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.language = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The language code value for the language in which the quick response is written.</p>
    pub fn set_language(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.language = input;
        self
    }
    /// <p>The language code value for the language in which the quick response is written.</p>
    pub fn get_language(&self) -> &::std::option::Option<::std::string::String> {
        &self.language
    }
    /// Appends an item to `attributes_not_interpolated`.
    ///
    /// To override the contents of this collection use [`set_attributes_not_interpolated`](Self::set_attributes_not_interpolated).
    ///
    /// <p>The user defined contact attributes that are not resolved when the search result is returned.</p>
    pub fn attributes_not_interpolated(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.attributes_not_interpolated.unwrap_or_default();
        v.push(input.into());
        self.attributes_not_interpolated = ::std::option::Option::Some(v);
        self
    }
    /// <p>The user defined contact attributes that are not resolved when the search result is returned.</p>
    pub fn set_attributes_not_interpolated(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.attributes_not_interpolated = input;
        self
    }
    /// <p>The user defined contact attributes that are not resolved when the search result is returned.</p>
    pub fn get_attributes_not_interpolated(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.attributes_not_interpolated
    }
    /// Appends an item to `attributes_interpolated`.
    ///
    /// To override the contents of this collection use [`set_attributes_interpolated`](Self::set_attributes_interpolated).
    ///
    /// <p>The user defined contact attributes that are resolved when the search result is returned.</p>
    pub fn attributes_interpolated(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.attributes_interpolated.unwrap_or_default();
        v.push(input.into());
        self.attributes_interpolated = ::std::option::Option::Some(v);
        self
    }
    /// <p>The user defined contact attributes that are resolved when the search result is returned.</p>
    pub fn set_attributes_interpolated(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.attributes_interpolated = input;
        self
    }
    /// <p>The user defined contact attributes that are resolved when the search result is returned.</p>
    pub fn get_attributes_interpolated(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.attributes_interpolated
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
    /// Consumes the builder and constructs a [`QuickResponseSearchResultData`](crate::types::QuickResponseSearchResultData).
    /// This method will fail if any of the following fields are not set:
    /// - [`quick_response_arn`](crate::types::builders::QuickResponseSearchResultDataBuilder::quick_response_arn)
    /// - [`quick_response_id`](crate::types::builders::QuickResponseSearchResultDataBuilder::quick_response_id)
    /// - [`knowledge_base_arn`](crate::types::builders::QuickResponseSearchResultDataBuilder::knowledge_base_arn)
    /// - [`knowledge_base_id`](crate::types::builders::QuickResponseSearchResultDataBuilder::knowledge_base_id)
    /// - [`name`](crate::types::builders::QuickResponseSearchResultDataBuilder::name)
    /// - [`content_type`](crate::types::builders::QuickResponseSearchResultDataBuilder::content_type)
    /// - [`status`](crate::types::builders::QuickResponseSearchResultDataBuilder::status)
    /// - [`created_time`](crate::types::builders::QuickResponseSearchResultDataBuilder::created_time)
    /// - [`last_modified_time`](crate::types::builders::QuickResponseSearchResultDataBuilder::last_modified_time)
    /// - [`is_active`](crate::types::builders::QuickResponseSearchResultDataBuilder::is_active)
    pub fn build(self) -> ::std::result::Result<crate::types::QuickResponseSearchResultData, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::QuickResponseSearchResultData {
            quick_response_arn: self.quick_response_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "quick_response_arn",
                    "quick_response_arn was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            quick_response_id: self.quick_response_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "quick_response_id",
                    "quick_response_id was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            knowledge_base_arn: self.knowledge_base_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "knowledge_base_arn",
                    "knowledge_base_arn was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            knowledge_base_id: self.knowledge_base_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "knowledge_base_id",
                    "knowledge_base_id was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            content_type: self.content_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "content_type",
                    "content_type was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            contents: self.contents,
            created_time: self.created_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_time",
                    "created_time was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            last_modified_time: self.last_modified_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_time",
                    "last_modified_time was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            is_active: self.is_active.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "is_active",
                    "is_active was not specified but it is required when building QuickResponseSearchResultData",
                )
            })?,
            description: self.description,
            grouping_configuration: self.grouping_configuration,
            shortcut_key: self.shortcut_key,
            last_modified_by: self.last_modified_by,
            channels: self.channels,
            language: self.language,
            attributes_not_interpolated: self.attributes_not_interpolated,
            attributes_interpolated: self.attributes_interpolated,
            tags: self.tags,
        })
    }
}
impl ::std::fmt::Debug for QuickResponseSearchResultDataBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("QuickResponseSearchResultDataBuilder");
        formatter.field("quick_response_arn", &self.quick_response_arn);
        formatter.field("quick_response_id", &self.quick_response_id);
        formatter.field("knowledge_base_arn", &self.knowledge_base_arn);
        formatter.field("knowledge_base_id", &self.knowledge_base_id);
        formatter.field("name", &self.name);
        formatter.field("content_type", &self.content_type);
        formatter.field("status", &self.status);
        formatter.field("contents", &self.contents);
        formatter.field("created_time", &self.created_time);
        formatter.field("last_modified_time", &self.last_modified_time);
        formatter.field("is_active", &self.is_active);
        formatter.field("description", &self.description);
        formatter.field("grouping_configuration", &self.grouping_configuration);
        formatter.field("shortcut_key", &self.shortcut_key);
        formatter.field("last_modified_by", &self.last_modified_by);
        formatter.field("channels", &"*** Sensitive Data Redacted ***");
        formatter.field("language", &self.language);
        formatter.field("attributes_not_interpolated", &"*** Sensitive Data Redacted ***");
        formatter.field("attributes_interpolated", &"*** Sensitive Data Redacted ***");
        formatter.field("tags", &self.tags);
        formatter.finish()
    }
}
