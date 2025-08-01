// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateStackInput {
    /// <p>The name of the stack.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The description to display.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The stack name to display.</p>
    pub display_name: ::std::option::Option<::std::string::String>,
    /// <p>The storage connectors to enable.</p>
    pub storage_connectors: ::std::option::Option<::std::vec::Vec<crate::types::StorageConnector>>,
    /// <p>The URL that users are redirected to after their streaming session ends.</p>
    pub redirect_url: ::std::option::Option<::std::string::String>,
    /// <p>The URL that users are redirected to after they click the Send Feedback link. If no URL is specified, no Send Feedback link is displayed.</p>
    pub feedback_url: ::std::option::Option<::std::string::String>,
    /// <p>The actions that are enabled or disabled for users during their streaming sessions. By default, these actions are enabled.</p>
    pub user_settings: ::std::option::Option<::std::vec::Vec<crate::types::UserSetting>>,
    /// <p>The persistent application settings for users of a stack. When these settings are enabled, changes that users make to applications and Windows settings are automatically saved after each session and applied to the next session.</p>
    pub application_settings: ::std::option::Option<crate::types::ApplicationSettings>,
    /// <p>The tags to associate with the stack. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The list of interface VPC endpoint (interface endpoint) objects. Users of the stack can connect to AppStream 2.0 only through the specified endpoints.</p>
    pub access_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::AccessEndpoint>>,
    /// <p>The domains where AppStream 2.0 streaming sessions can be embedded in an iframe. You must approve the domains that you want to host embedded AppStream 2.0 streaming sessions.</p>
    pub embed_host_domains: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The streaming protocol you want your stack to prefer. This can be UDP or TCP. Currently, UDP is only supported in the Windows native client.</p>
    pub streaming_experience_settings: ::std::option::Option<crate::types::StreamingExperienceSettings>,
}
impl CreateStackInput {
    /// <p>The name of the stack.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The description to display.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The stack name to display.</p>
    pub fn display_name(&self) -> ::std::option::Option<&str> {
        self.display_name.as_deref()
    }
    /// <p>The storage connectors to enable.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.storage_connectors.is_none()`.
    pub fn storage_connectors(&self) -> &[crate::types::StorageConnector] {
        self.storage_connectors.as_deref().unwrap_or_default()
    }
    /// <p>The URL that users are redirected to after their streaming session ends.</p>
    pub fn redirect_url(&self) -> ::std::option::Option<&str> {
        self.redirect_url.as_deref()
    }
    /// <p>The URL that users are redirected to after they click the Send Feedback link. If no URL is specified, no Send Feedback link is displayed.</p>
    pub fn feedback_url(&self) -> ::std::option::Option<&str> {
        self.feedback_url.as_deref()
    }
    /// <p>The actions that are enabled or disabled for users during their streaming sessions. By default, these actions are enabled.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_settings.is_none()`.
    pub fn user_settings(&self) -> &[crate::types::UserSetting] {
        self.user_settings.as_deref().unwrap_or_default()
    }
    /// <p>The persistent application settings for users of a stack. When these settings are enabled, changes that users make to applications and Windows settings are automatically saved after each session and applied to the next session.</p>
    pub fn application_settings(&self) -> ::std::option::Option<&crate::types::ApplicationSettings> {
        self.application_settings.as_ref()
    }
    /// <p>The tags to associate with the stack. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The list of interface VPC endpoint (interface endpoint) objects. Users of the stack can connect to AppStream 2.0 only through the specified endpoints.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.access_endpoints.is_none()`.
    pub fn access_endpoints(&self) -> &[crate::types::AccessEndpoint] {
        self.access_endpoints.as_deref().unwrap_or_default()
    }
    /// <p>The domains where AppStream 2.0 streaming sessions can be embedded in an iframe. You must approve the domains that you want to host embedded AppStream 2.0 streaming sessions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.embed_host_domains.is_none()`.
    pub fn embed_host_domains(&self) -> &[::std::string::String] {
        self.embed_host_domains.as_deref().unwrap_or_default()
    }
    /// <p>The streaming protocol you want your stack to prefer. This can be UDP or TCP. Currently, UDP is only supported in the Windows native client.</p>
    pub fn streaming_experience_settings(&self) -> ::std::option::Option<&crate::types::StreamingExperienceSettings> {
        self.streaming_experience_settings.as_ref()
    }
}
impl CreateStackInput {
    /// Creates a new builder-style object to manufacture [`CreateStackInput`](crate::operation::create_stack::CreateStackInput).
    pub fn builder() -> crate::operation::create_stack::builders::CreateStackInputBuilder {
        crate::operation::create_stack::builders::CreateStackInputBuilder::default()
    }
}

/// A builder for [`CreateStackInput`](crate::operation::create_stack::CreateStackInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateStackInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) display_name: ::std::option::Option<::std::string::String>,
    pub(crate) storage_connectors: ::std::option::Option<::std::vec::Vec<crate::types::StorageConnector>>,
    pub(crate) redirect_url: ::std::option::Option<::std::string::String>,
    pub(crate) feedback_url: ::std::option::Option<::std::string::String>,
    pub(crate) user_settings: ::std::option::Option<::std::vec::Vec<crate::types::UserSetting>>,
    pub(crate) application_settings: ::std::option::Option<crate::types::ApplicationSettings>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) access_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::AccessEndpoint>>,
    pub(crate) embed_host_domains: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) streaming_experience_settings: ::std::option::Option<crate::types::StreamingExperienceSettings>,
}
impl CreateStackInputBuilder {
    /// <p>The name of the stack.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stack.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the stack.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description to display.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description to display.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description to display.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The stack name to display.</p>
    pub fn display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stack name to display.</p>
    pub fn set_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.display_name = input;
        self
    }
    /// <p>The stack name to display.</p>
    pub fn get_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.display_name
    }
    /// Appends an item to `storage_connectors`.
    ///
    /// To override the contents of this collection use [`set_storage_connectors`](Self::set_storage_connectors).
    ///
    /// <p>The storage connectors to enable.</p>
    pub fn storage_connectors(mut self, input: crate::types::StorageConnector) -> Self {
        let mut v = self.storage_connectors.unwrap_or_default();
        v.push(input);
        self.storage_connectors = ::std::option::Option::Some(v);
        self
    }
    /// <p>The storage connectors to enable.</p>
    pub fn set_storage_connectors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StorageConnector>>) -> Self {
        self.storage_connectors = input;
        self
    }
    /// <p>The storage connectors to enable.</p>
    pub fn get_storage_connectors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StorageConnector>> {
        &self.storage_connectors
    }
    /// <p>The URL that users are redirected to after their streaming session ends.</p>
    pub fn redirect_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.redirect_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL that users are redirected to after their streaming session ends.</p>
    pub fn set_redirect_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.redirect_url = input;
        self
    }
    /// <p>The URL that users are redirected to after their streaming session ends.</p>
    pub fn get_redirect_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.redirect_url
    }
    /// <p>The URL that users are redirected to after they click the Send Feedback link. If no URL is specified, no Send Feedback link is displayed.</p>
    pub fn feedback_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.feedback_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL that users are redirected to after they click the Send Feedback link. If no URL is specified, no Send Feedback link is displayed.</p>
    pub fn set_feedback_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.feedback_url = input;
        self
    }
    /// <p>The URL that users are redirected to after they click the Send Feedback link. If no URL is specified, no Send Feedback link is displayed.</p>
    pub fn get_feedback_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.feedback_url
    }
    /// Appends an item to `user_settings`.
    ///
    /// To override the contents of this collection use [`set_user_settings`](Self::set_user_settings).
    ///
    /// <p>The actions that are enabled or disabled for users during their streaming sessions. By default, these actions are enabled.</p>
    pub fn user_settings(mut self, input: crate::types::UserSetting) -> Self {
        let mut v = self.user_settings.unwrap_or_default();
        v.push(input);
        self.user_settings = ::std::option::Option::Some(v);
        self
    }
    /// <p>The actions that are enabled or disabled for users during their streaming sessions. By default, these actions are enabled.</p>
    pub fn set_user_settings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UserSetting>>) -> Self {
        self.user_settings = input;
        self
    }
    /// <p>The actions that are enabled or disabled for users during their streaming sessions. By default, these actions are enabled.</p>
    pub fn get_user_settings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UserSetting>> {
        &self.user_settings
    }
    /// <p>The persistent application settings for users of a stack. When these settings are enabled, changes that users make to applications and Windows settings are automatically saved after each session and applied to the next session.</p>
    pub fn application_settings(mut self, input: crate::types::ApplicationSettings) -> Self {
        self.application_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The persistent application settings for users of a stack. When these settings are enabled, changes that users make to applications and Windows settings are automatically saved after each session and applied to the next session.</p>
    pub fn set_application_settings(mut self, input: ::std::option::Option<crate::types::ApplicationSettings>) -> Self {
        self.application_settings = input;
        self
    }
    /// <p>The persistent application settings for users of a stack. When these settings are enabled, changes that users make to applications and Windows settings are automatically saved after each session and applied to the next session.</p>
    pub fn get_application_settings(&self) -> &::std::option::Option<crate::types::ApplicationSettings> {
        &self.application_settings
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to associate with the stack. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags to associate with the stack. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to associate with the stack. A tag is a key-value pair, and the value is optional. For example, Environment=Test. If you do not specify a value, Environment=.</p>
    /// <p>If you do not specify a value, the value is set to an empty string.</p>
    /// <p>Generally allowed characters are: letters, numbers, and spaces representable in UTF-8, and the following special characters:</p>
    /// <p>_ . : / = + \ - @</p>
    /// <p>For more information about tags, see <a href="https://docs.aws.amazon.com/appstream2/latest/developerguide/tagging-basic.html">Tagging Your Resources</a> in the <i>Amazon AppStream 2.0 Administration Guide</i>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Appends an item to `access_endpoints`.
    ///
    /// To override the contents of this collection use [`set_access_endpoints`](Self::set_access_endpoints).
    ///
    /// <p>The list of interface VPC endpoint (interface endpoint) objects. Users of the stack can connect to AppStream 2.0 only through the specified endpoints.</p>
    pub fn access_endpoints(mut self, input: crate::types::AccessEndpoint) -> Self {
        let mut v = self.access_endpoints.unwrap_or_default();
        v.push(input);
        self.access_endpoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of interface VPC endpoint (interface endpoint) objects. Users of the stack can connect to AppStream 2.0 only through the specified endpoints.</p>
    pub fn set_access_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AccessEndpoint>>) -> Self {
        self.access_endpoints = input;
        self
    }
    /// <p>The list of interface VPC endpoint (interface endpoint) objects. Users of the stack can connect to AppStream 2.0 only through the specified endpoints.</p>
    pub fn get_access_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AccessEndpoint>> {
        &self.access_endpoints
    }
    /// Appends an item to `embed_host_domains`.
    ///
    /// To override the contents of this collection use [`set_embed_host_domains`](Self::set_embed_host_domains).
    ///
    /// <p>The domains where AppStream 2.0 streaming sessions can be embedded in an iframe. You must approve the domains that you want to host embedded AppStream 2.0 streaming sessions.</p>
    pub fn embed_host_domains(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.embed_host_domains.unwrap_or_default();
        v.push(input.into());
        self.embed_host_domains = ::std::option::Option::Some(v);
        self
    }
    /// <p>The domains where AppStream 2.0 streaming sessions can be embedded in an iframe. You must approve the domains that you want to host embedded AppStream 2.0 streaming sessions.</p>
    pub fn set_embed_host_domains(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.embed_host_domains = input;
        self
    }
    /// <p>The domains where AppStream 2.0 streaming sessions can be embedded in an iframe. You must approve the domains that you want to host embedded AppStream 2.0 streaming sessions.</p>
    pub fn get_embed_host_domains(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.embed_host_domains
    }
    /// <p>The streaming protocol you want your stack to prefer. This can be UDP or TCP. Currently, UDP is only supported in the Windows native client.</p>
    pub fn streaming_experience_settings(mut self, input: crate::types::StreamingExperienceSettings) -> Self {
        self.streaming_experience_settings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The streaming protocol you want your stack to prefer. This can be UDP or TCP. Currently, UDP is only supported in the Windows native client.</p>
    pub fn set_streaming_experience_settings(mut self, input: ::std::option::Option<crate::types::StreamingExperienceSettings>) -> Self {
        self.streaming_experience_settings = input;
        self
    }
    /// <p>The streaming protocol you want your stack to prefer. This can be UDP or TCP. Currently, UDP is only supported in the Windows native client.</p>
    pub fn get_streaming_experience_settings(&self) -> &::std::option::Option<crate::types::StreamingExperienceSettings> {
        &self.streaming_experience_settings
    }
    /// Consumes the builder and constructs a [`CreateStackInput`](crate::operation::create_stack::CreateStackInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_stack::CreateStackInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_stack::CreateStackInput {
            name: self.name,
            description: self.description,
            display_name: self.display_name,
            storage_connectors: self.storage_connectors,
            redirect_url: self.redirect_url,
            feedback_url: self.feedback_url,
            user_settings: self.user_settings,
            application_settings: self.application_settings,
            tags: self.tags,
            access_endpoints: self.access_endpoints,
            embed_host_domains: self.embed_host_domains,
            streaming_experience_settings: self.streaming_experience_settings,
        })
    }
}
