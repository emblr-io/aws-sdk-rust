// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of key groups, and the public keys in each key group, that CloudFront can use to verify the signatures of signed URLs and signed cookies.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActiveTrustedKeyGroups {
    /// <p>This field is <code>true</code> if any of the key groups have public keys that CloudFront can use to verify the signatures of signed URLs and signed cookies. If not, this field is <code>false</code>.</p>
    pub enabled: bool,
    /// <p>The number of key groups in the list.</p>
    pub quantity: i32,
    /// <p>A list of key groups, including the identifiers of the public keys in each key group that CloudFront can use to verify the signatures of signed URLs and signed cookies.</p>
    pub items: ::std::option::Option<::std::vec::Vec<crate::types::KgKeyPairIds>>,
}
impl ActiveTrustedKeyGroups {
    /// <p>This field is <code>true</code> if any of the key groups have public keys that CloudFront can use to verify the signatures of signed URLs and signed cookies. If not, this field is <code>false</code>.</p>
    pub fn enabled(&self) -> bool {
        self.enabled
    }
    /// <p>The number of key groups in the list.</p>
    pub fn quantity(&self) -> i32 {
        self.quantity
    }
    /// <p>A list of key groups, including the identifiers of the public keys in each key group that CloudFront can use to verify the signatures of signed URLs and signed cookies.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[crate::types::KgKeyPairIds] {
        self.items.as_deref().unwrap_or_default()
    }
}
impl ActiveTrustedKeyGroups {
    /// Creates a new builder-style object to manufacture [`ActiveTrustedKeyGroups`](crate::types::ActiveTrustedKeyGroups).
    pub fn builder() -> crate::types::builders::ActiveTrustedKeyGroupsBuilder {
        crate::types::builders::ActiveTrustedKeyGroupsBuilder::default()
    }
}

/// A builder for [`ActiveTrustedKeyGroups`](crate::types::ActiveTrustedKeyGroups).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActiveTrustedKeyGroupsBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) quantity: ::std::option::Option<i32>,
    pub(crate) items: ::std::option::Option<::std::vec::Vec<crate::types::KgKeyPairIds>>,
}
impl ActiveTrustedKeyGroupsBuilder {
    /// <p>This field is <code>true</code> if any of the key groups have public keys that CloudFront can use to verify the signatures of signed URLs and signed cookies. If not, this field is <code>false</code>.</p>
    /// This field is required.
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>This field is <code>true</code> if any of the key groups have public keys that CloudFront can use to verify the signatures of signed URLs and signed cookies. If not, this field is <code>false</code>.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>This field is <code>true</code> if any of the key groups have public keys that CloudFront can use to verify the signatures of signed URLs and signed cookies. If not, this field is <code>false</code>.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>The number of key groups in the list.</p>
    /// This field is required.
    pub fn quantity(mut self, input: i32) -> Self {
        self.quantity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of key groups in the list.</p>
    pub fn set_quantity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.quantity = input;
        self
    }
    /// <p>The number of key groups in the list.</p>
    pub fn get_quantity(&self) -> &::std::option::Option<i32> {
        &self.quantity
    }
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>A list of key groups, including the identifiers of the public keys in each key group that CloudFront can use to verify the signatures of signed URLs and signed cookies.</p>
    pub fn items(mut self, input: crate::types::KgKeyPairIds) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of key groups, including the identifiers of the public keys in each key group that CloudFront can use to verify the signatures of signed URLs and signed cookies.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::KgKeyPairIds>>) -> Self {
        self.items = input;
        self
    }
    /// <p>A list of key groups, including the identifiers of the public keys in each key group that CloudFront can use to verify the signatures of signed URLs and signed cookies.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::KgKeyPairIds>> {
        &self.items
    }
    /// Consumes the builder and constructs a [`ActiveTrustedKeyGroups`](crate::types::ActiveTrustedKeyGroups).
    /// This method will fail if any of the following fields are not set:
    /// - [`enabled`](crate::types::builders::ActiveTrustedKeyGroupsBuilder::enabled)
    /// - [`quantity`](crate::types::builders::ActiveTrustedKeyGroupsBuilder::quantity)
    pub fn build(self) -> ::std::result::Result<crate::types::ActiveTrustedKeyGroups, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ActiveTrustedKeyGroups {
            enabled: self.enabled.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "enabled",
                    "enabled was not specified but it is required when building ActiveTrustedKeyGroups",
                )
            })?,
            quantity: self.quantity.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "quantity",
                    "quantity was not specified but it is required when building ActiveTrustedKeyGroups",
                )
            })?,
            items: self.items,
        })
    }
}
