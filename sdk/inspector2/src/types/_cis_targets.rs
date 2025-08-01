// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The CIS targets.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CisTargets {
    /// <p>The CIS target account ids.</p>
    pub account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The CIS target resource tags.</p>
    pub target_resource_tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
}
impl CisTargets {
    /// <p>The CIS target account ids.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.account_ids.is_none()`.
    pub fn account_ids(&self) -> &[::std::string::String] {
        self.account_ids.as_deref().unwrap_or_default()
    }
    /// <p>The CIS target resource tags.</p>
    pub fn target_resource_tags(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        self.target_resource_tags.as_ref()
    }
}
impl CisTargets {
    /// Creates a new builder-style object to manufacture [`CisTargets`](crate::types::CisTargets).
    pub fn builder() -> crate::types::builders::CisTargetsBuilder {
        crate::types::builders::CisTargetsBuilder::default()
    }
}

/// A builder for [`CisTargets`](crate::types::CisTargets).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CisTargetsBuilder {
    pub(crate) account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) target_resource_tags:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
}
impl CisTargetsBuilder {
    /// Appends an item to `account_ids`.
    ///
    /// To override the contents of this collection use [`set_account_ids`](Self::set_account_ids).
    ///
    /// <p>The CIS target account ids.</p>
    pub fn account_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.account_ids.unwrap_or_default();
        v.push(input.into());
        self.account_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The CIS target account ids.</p>
    pub fn set_account_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.account_ids = input;
        self
    }
    /// <p>The CIS target account ids.</p>
    pub fn get_account_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.account_ids
    }
    /// Adds a key-value pair to `target_resource_tags`.
    ///
    /// To override the contents of this collection use [`set_target_resource_tags`](Self::set_target_resource_tags).
    ///
    /// <p>The CIS target resource tags.</p>
    pub fn target_resource_tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.target_resource_tags.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.target_resource_tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The CIS target resource tags.</p>
    pub fn set_target_resource_tags(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    ) -> Self {
        self.target_resource_tags = input;
        self
    }
    /// <p>The CIS target resource tags.</p>
    pub fn get_target_resource_tags(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        &self.target_resource_tags
    }
    /// Consumes the builder and constructs a [`CisTargets`](crate::types::CisTargets).
    pub fn build(self) -> crate::types::CisTargets {
        crate::types::CisTargets {
            account_ids: self.account_ids,
            target_resource_tags: self.target_resource_tags,
        }
    }
}
