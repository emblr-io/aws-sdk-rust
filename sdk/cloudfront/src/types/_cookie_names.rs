// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains a list of cookie names.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CookieNames {
    /// <p>The number of cookie names in the <code>Items</code> list.</p>
    pub quantity: i32,
    /// <p>A list of cookie names.</p>
    pub items: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CookieNames {
    /// <p>The number of cookie names in the <code>Items</code> list.</p>
    pub fn quantity(&self) -> i32 {
        self.quantity
    }
    /// <p>A list of cookie names.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[::std::string::String] {
        self.items.as_deref().unwrap_or_default()
    }
}
impl CookieNames {
    /// Creates a new builder-style object to manufacture [`CookieNames`](crate::types::CookieNames).
    pub fn builder() -> crate::types::builders::CookieNamesBuilder {
        crate::types::builders::CookieNamesBuilder::default()
    }
}

/// A builder for [`CookieNames`](crate::types::CookieNames).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CookieNamesBuilder {
    pub(crate) quantity: ::std::option::Option<i32>,
    pub(crate) items: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CookieNamesBuilder {
    /// <p>The number of cookie names in the <code>Items</code> list.</p>
    /// This field is required.
    pub fn quantity(mut self, input: i32) -> Self {
        self.quantity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of cookie names in the <code>Items</code> list.</p>
    pub fn set_quantity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.quantity = input;
        self
    }
    /// <p>The number of cookie names in the <code>Items</code> list.</p>
    pub fn get_quantity(&self) -> &::std::option::Option<i32> {
        &self.quantity
    }
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>A list of cookie names.</p>
    pub fn items(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input.into());
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of cookie names.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.items = input;
        self
    }
    /// <p>A list of cookie names.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.items
    }
    /// Consumes the builder and constructs a [`CookieNames`](crate::types::CookieNames).
    /// This method will fail if any of the following fields are not set:
    /// - [`quantity`](crate::types::builders::CookieNamesBuilder::quantity)
    pub fn build(self) -> ::std::result::Result<crate::types::CookieNames, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CookieNames {
            quantity: self.quantity.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "quantity",
                    "quantity was not specified but it is required when building CookieNames",
                )
            })?,
            items: self.items,
        })
    }
}
