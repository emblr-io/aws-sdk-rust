// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTargetGroupInput {
    /// <p>The name of the target group. The name must be unique within the account. The valid characters are a-z, 0-9, and hyphens (-). You can't use a hyphen as the first or last character, or immediately after another hyphen.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of target group.</p>
    pub r#type: ::std::option::Option<crate::types::TargetGroupType>,
    /// <p>The target group configuration.</p>
    pub config: ::std::option::Option<crate::types::TargetGroupConfig>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you retry a request that completed successfully using the same client token and parameters, the retry succeeds without performing any actions. If the parameters aren't identical, the retry fails.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The tags for the target group.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateTargetGroupInput {
    /// <p>The name of the target group. The name must be unique within the account. The valid characters are a-z, 0-9, and hyphens (-). You can't use a hyphen as the first or last character, or immediately after another hyphen.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of target group.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::TargetGroupType> {
        self.r#type.as_ref()
    }
    /// <p>The target group configuration.</p>
    pub fn config(&self) -> ::std::option::Option<&crate::types::TargetGroupConfig> {
        self.config.as_ref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you retry a request that completed successfully using the same client token and parameters, the retry succeeds without performing any actions. If the parameters aren't identical, the retry fails.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The tags for the target group.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateTargetGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateTargetGroupInput`](crate::operation::create_target_group::CreateTargetGroupInput).
    pub fn builder() -> crate::operation::create_target_group::builders::CreateTargetGroupInputBuilder {
        crate::operation::create_target_group::builders::CreateTargetGroupInputBuilder::default()
    }
}

/// A builder for [`CreateTargetGroupInput`](crate::operation::create_target_group::CreateTargetGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTargetGroupInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::TargetGroupType>,
    pub(crate) config: ::std::option::Option<crate::types::TargetGroupConfig>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateTargetGroupInputBuilder {
    /// <p>The name of the target group. The name must be unique within the account. The valid characters are a-z, 0-9, and hyphens (-). You can't use a hyphen as the first or last character, or immediately after another hyphen.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the target group. The name must be unique within the account. The valid characters are a-z, 0-9, and hyphens (-). You can't use a hyphen as the first or last character, or immediately after another hyphen.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the target group. The name must be unique within the account. The valid characters are a-z, 0-9, and hyphens (-). You can't use a hyphen as the first or last character, or immediately after another hyphen.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of target group.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::TargetGroupType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of target group.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::TargetGroupType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of target group.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::TargetGroupType> {
        &self.r#type
    }
    /// <p>The target group configuration.</p>
    pub fn config(mut self, input: crate::types::TargetGroupConfig) -> Self {
        self.config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The target group configuration.</p>
    pub fn set_config(mut self, input: ::std::option::Option<crate::types::TargetGroupConfig>) -> Self {
        self.config = input;
        self
    }
    /// <p>The target group configuration.</p>
    pub fn get_config(&self) -> &::std::option::Option<crate::types::TargetGroupConfig> {
        &self.config
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you retry a request that completed successfully using the same client token and parameters, the retry succeeds without performing any actions. If the parameters aren't identical, the retry fails.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you retry a request that completed successfully using the same client token and parameters, the retry succeeds without performing any actions. If the parameters aren't identical, the retry fails.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request. If you retry a request that completed successfully using the same client token and parameters, the retry succeeds without performing any actions. If the parameters aren't identical, the retry fails.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags for the target group.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags for the target group.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags for the target group.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateTargetGroupInput`](crate::operation::create_target_group::CreateTargetGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_target_group::CreateTargetGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_target_group::CreateTargetGroupInput {
            name: self.name,
            r#type: self.r#type,
            config: self.config,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
