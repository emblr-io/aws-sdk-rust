// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateHubContentInput {
    /// <p>The name of the SageMaker hub that contains the hub content you want to update. You can optionally use the hub ARN instead.</p>
    pub hub_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the hub content resource that you want to update.</p>
    pub hub_content_name: ::std::option::Option<::std::string::String>,
    /// <p>The content type of the resource that you want to update. Only specify a <code>Model</code> or <code>Notebook</code> resource for this API. To update a <code>ModelReference</code>, use the <code>UpdateHubContentReference</code> API instead.</p>
    pub hub_content_type: ::std::option::Option<crate::types::HubContentType>,
    /// <p>The hub content version that you want to update. For example, if you have two versions of a resource in your hub, you can update the second version.</p>
    pub hub_content_version: ::std::option::Option<::std::string::String>,
    /// <p>The display name of the hub content.</p>
    pub hub_content_display_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the hub content.</p>
    pub hub_content_description: ::std::option::Option<::std::string::String>,
    /// <p>A string that provides a description of the hub content. This string can include links, tables, and standard markdown formatting.</p>
    pub hub_content_markdown: ::std::option::Option<::std::string::String>,
    /// <p>The searchable keywords of the hub content.</p>
    pub hub_content_search_keywords: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Indicates the current status of the hub content resource.</p>
    pub support_status: ::std::option::Option<crate::types::HubContentSupportStatus>,
}
impl UpdateHubContentInput {
    /// <p>The name of the SageMaker hub that contains the hub content you want to update. You can optionally use the hub ARN instead.</p>
    pub fn hub_name(&self) -> ::std::option::Option<&str> {
        self.hub_name.as_deref()
    }
    /// <p>The name of the hub content resource that you want to update.</p>
    pub fn hub_content_name(&self) -> ::std::option::Option<&str> {
        self.hub_content_name.as_deref()
    }
    /// <p>The content type of the resource that you want to update. Only specify a <code>Model</code> or <code>Notebook</code> resource for this API. To update a <code>ModelReference</code>, use the <code>UpdateHubContentReference</code> API instead.</p>
    pub fn hub_content_type(&self) -> ::std::option::Option<&crate::types::HubContentType> {
        self.hub_content_type.as_ref()
    }
    /// <p>The hub content version that you want to update. For example, if you have two versions of a resource in your hub, you can update the second version.</p>
    pub fn hub_content_version(&self) -> ::std::option::Option<&str> {
        self.hub_content_version.as_deref()
    }
    /// <p>The display name of the hub content.</p>
    pub fn hub_content_display_name(&self) -> ::std::option::Option<&str> {
        self.hub_content_display_name.as_deref()
    }
    /// <p>The description of the hub content.</p>
    pub fn hub_content_description(&self) -> ::std::option::Option<&str> {
        self.hub_content_description.as_deref()
    }
    /// <p>A string that provides a description of the hub content. This string can include links, tables, and standard markdown formatting.</p>
    pub fn hub_content_markdown(&self) -> ::std::option::Option<&str> {
        self.hub_content_markdown.as_deref()
    }
    /// <p>The searchable keywords of the hub content.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.hub_content_search_keywords.is_none()`.
    pub fn hub_content_search_keywords(&self) -> &[::std::string::String] {
        self.hub_content_search_keywords.as_deref().unwrap_or_default()
    }
    /// <p>Indicates the current status of the hub content resource.</p>
    pub fn support_status(&self) -> ::std::option::Option<&crate::types::HubContentSupportStatus> {
        self.support_status.as_ref()
    }
}
impl UpdateHubContentInput {
    /// Creates a new builder-style object to manufacture [`UpdateHubContentInput`](crate::operation::update_hub_content::UpdateHubContentInput).
    pub fn builder() -> crate::operation::update_hub_content::builders::UpdateHubContentInputBuilder {
        crate::operation::update_hub_content::builders::UpdateHubContentInputBuilder::default()
    }
}

/// A builder for [`UpdateHubContentInput`](crate::operation::update_hub_content::UpdateHubContentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateHubContentInputBuilder {
    pub(crate) hub_name: ::std::option::Option<::std::string::String>,
    pub(crate) hub_content_name: ::std::option::Option<::std::string::String>,
    pub(crate) hub_content_type: ::std::option::Option<crate::types::HubContentType>,
    pub(crate) hub_content_version: ::std::option::Option<::std::string::String>,
    pub(crate) hub_content_display_name: ::std::option::Option<::std::string::String>,
    pub(crate) hub_content_description: ::std::option::Option<::std::string::String>,
    pub(crate) hub_content_markdown: ::std::option::Option<::std::string::String>,
    pub(crate) hub_content_search_keywords: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) support_status: ::std::option::Option<crate::types::HubContentSupportStatus>,
}
impl UpdateHubContentInputBuilder {
    /// <p>The name of the SageMaker hub that contains the hub content you want to update. You can optionally use the hub ARN instead.</p>
    /// This field is required.
    pub fn hub_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the SageMaker hub that contains the hub content you want to update. You can optionally use the hub ARN instead.</p>
    pub fn set_hub_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_name = input;
        self
    }
    /// <p>The name of the SageMaker hub that contains the hub content you want to update. You can optionally use the hub ARN instead.</p>
    pub fn get_hub_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_name
    }
    /// <p>The name of the hub content resource that you want to update.</p>
    /// This field is required.
    pub fn hub_content_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_content_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the hub content resource that you want to update.</p>
    pub fn set_hub_content_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_content_name = input;
        self
    }
    /// <p>The name of the hub content resource that you want to update.</p>
    pub fn get_hub_content_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_content_name
    }
    /// <p>The content type of the resource that you want to update. Only specify a <code>Model</code> or <code>Notebook</code> resource for this API. To update a <code>ModelReference</code>, use the <code>UpdateHubContentReference</code> API instead.</p>
    /// This field is required.
    pub fn hub_content_type(mut self, input: crate::types::HubContentType) -> Self {
        self.hub_content_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The content type of the resource that you want to update. Only specify a <code>Model</code> or <code>Notebook</code> resource for this API. To update a <code>ModelReference</code>, use the <code>UpdateHubContentReference</code> API instead.</p>
    pub fn set_hub_content_type(mut self, input: ::std::option::Option<crate::types::HubContentType>) -> Self {
        self.hub_content_type = input;
        self
    }
    /// <p>The content type of the resource that you want to update. Only specify a <code>Model</code> or <code>Notebook</code> resource for this API. To update a <code>ModelReference</code>, use the <code>UpdateHubContentReference</code> API instead.</p>
    pub fn get_hub_content_type(&self) -> &::std::option::Option<crate::types::HubContentType> {
        &self.hub_content_type
    }
    /// <p>The hub content version that you want to update. For example, if you have two versions of a resource in your hub, you can update the second version.</p>
    /// This field is required.
    pub fn hub_content_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_content_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The hub content version that you want to update. For example, if you have two versions of a resource in your hub, you can update the second version.</p>
    pub fn set_hub_content_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_content_version = input;
        self
    }
    /// <p>The hub content version that you want to update. For example, if you have two versions of a resource in your hub, you can update the second version.</p>
    pub fn get_hub_content_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_content_version
    }
    /// <p>The display name of the hub content.</p>
    pub fn hub_content_display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_content_display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The display name of the hub content.</p>
    pub fn set_hub_content_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_content_display_name = input;
        self
    }
    /// <p>The display name of the hub content.</p>
    pub fn get_hub_content_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_content_display_name
    }
    /// <p>The description of the hub content.</p>
    pub fn hub_content_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_content_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the hub content.</p>
    pub fn set_hub_content_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_content_description = input;
        self
    }
    /// <p>The description of the hub content.</p>
    pub fn get_hub_content_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_content_description
    }
    /// <p>A string that provides a description of the hub content. This string can include links, tables, and standard markdown formatting.</p>
    pub fn hub_content_markdown(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hub_content_markdown = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string that provides a description of the hub content. This string can include links, tables, and standard markdown formatting.</p>
    pub fn set_hub_content_markdown(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hub_content_markdown = input;
        self
    }
    /// <p>A string that provides a description of the hub content. This string can include links, tables, and standard markdown formatting.</p>
    pub fn get_hub_content_markdown(&self) -> &::std::option::Option<::std::string::String> {
        &self.hub_content_markdown
    }
    /// Appends an item to `hub_content_search_keywords`.
    ///
    /// To override the contents of this collection use [`set_hub_content_search_keywords`](Self::set_hub_content_search_keywords).
    ///
    /// <p>The searchable keywords of the hub content.</p>
    pub fn hub_content_search_keywords(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.hub_content_search_keywords.unwrap_or_default();
        v.push(input.into());
        self.hub_content_search_keywords = ::std::option::Option::Some(v);
        self
    }
    /// <p>The searchable keywords of the hub content.</p>
    pub fn set_hub_content_search_keywords(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.hub_content_search_keywords = input;
        self
    }
    /// <p>The searchable keywords of the hub content.</p>
    pub fn get_hub_content_search_keywords(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.hub_content_search_keywords
    }
    /// <p>Indicates the current status of the hub content resource.</p>
    pub fn support_status(mut self, input: crate::types::HubContentSupportStatus) -> Self {
        self.support_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the current status of the hub content resource.</p>
    pub fn set_support_status(mut self, input: ::std::option::Option<crate::types::HubContentSupportStatus>) -> Self {
        self.support_status = input;
        self
    }
    /// <p>Indicates the current status of the hub content resource.</p>
    pub fn get_support_status(&self) -> &::std::option::Option<crate::types::HubContentSupportStatus> {
        &self.support_status
    }
    /// Consumes the builder and constructs a [`UpdateHubContentInput`](crate::operation::update_hub_content::UpdateHubContentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_hub_content::UpdateHubContentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_hub_content::UpdateHubContentInput {
            hub_name: self.hub_name,
            hub_content_name: self.hub_content_name,
            hub_content_type: self.hub_content_type,
            hub_content_version: self.hub_content_version,
            hub_content_display_name: self.hub_content_display_name,
            hub_content_description: self.hub_content_description,
            hub_content_markdown: self.hub_content_markdown,
            hub_content_search_keywords: self.hub_content_search_keywords,
            support_status: self.support_status,
        })
    }
}
