// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnableSecurityHubV2Input {
    /// <p>The tags to add to the hub V2 resource when you enable Security Hub.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl EnableSecurityHubV2Input {
    /// <p>The tags to add to the hub V2 resource when you enable Security Hub.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl EnableSecurityHubV2Input {
    /// Creates a new builder-style object to manufacture [`EnableSecurityHubV2Input`](crate::operation::enable_security_hub_v2::EnableSecurityHubV2Input).
    pub fn builder() -> crate::operation::enable_security_hub_v2::builders::EnableSecurityHubV2InputBuilder {
        crate::operation::enable_security_hub_v2::builders::EnableSecurityHubV2InputBuilder::default()
    }
}

/// A builder for [`EnableSecurityHubV2Input`](crate::operation::enable_security_hub_v2::EnableSecurityHubV2Input).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnableSecurityHubV2InputBuilder {
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl EnableSecurityHubV2InputBuilder {
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to add to the hub V2 resource when you enable Security Hub.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags to add to the hub V2 resource when you enable Security Hub.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to add to the hub V2 resource when you enable Security Hub.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`EnableSecurityHubV2Input`](crate::operation::enable_security_hub_v2::EnableSecurityHubV2Input).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::enable_security_hub_v2::EnableSecurityHubV2Input, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::enable_security_hub_v2::EnableSecurityHubV2Input { tags: self.tags })
    }
}
