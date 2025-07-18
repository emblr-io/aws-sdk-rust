// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex type that controls:</p>
/// <ul>
/// <li>
/// <p>Whether CloudFront replaces HTTP status codes in the 4xx and 5xx range with custom error messages before returning the response to the viewer.</p></li>
/// <li>
/// <p>How long CloudFront caches HTTP status codes in the 4xx and 5xx range.</p></li>
/// </ul>
/// <p>For more information about custom error pages, see <a href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/custom-error-pages.html">Customizing Error Responses</a> in the <i>Amazon CloudFront Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomErrorResponses {
    /// <p>The number of HTTP status codes for which you want to specify a custom error page and/or a caching duration. If <code>Quantity</code> is <code>0</code>, you can omit <code>Items</code>.</p>
    pub quantity: i32,
    /// <p>A complex type that contains a <code>CustomErrorResponse</code> element for each HTTP status code for which you want to specify a custom error page and/or a caching duration.</p>
    pub items: ::std::option::Option<::std::vec::Vec<crate::types::CustomErrorResponse>>,
}
impl CustomErrorResponses {
    /// <p>The number of HTTP status codes for which you want to specify a custom error page and/or a caching duration. If <code>Quantity</code> is <code>0</code>, you can omit <code>Items</code>.</p>
    pub fn quantity(&self) -> i32 {
        self.quantity
    }
    /// <p>A complex type that contains a <code>CustomErrorResponse</code> element for each HTTP status code for which you want to specify a custom error page and/or a caching duration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[crate::types::CustomErrorResponse] {
        self.items.as_deref().unwrap_or_default()
    }
}
impl CustomErrorResponses {
    /// Creates a new builder-style object to manufacture [`CustomErrorResponses`](crate::types::CustomErrorResponses).
    pub fn builder() -> crate::types::builders::CustomErrorResponsesBuilder {
        crate::types::builders::CustomErrorResponsesBuilder::default()
    }
}

/// A builder for [`CustomErrorResponses`](crate::types::CustomErrorResponses).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomErrorResponsesBuilder {
    pub(crate) quantity: ::std::option::Option<i32>,
    pub(crate) items: ::std::option::Option<::std::vec::Vec<crate::types::CustomErrorResponse>>,
}
impl CustomErrorResponsesBuilder {
    /// <p>The number of HTTP status codes for which you want to specify a custom error page and/or a caching duration. If <code>Quantity</code> is <code>0</code>, you can omit <code>Items</code>.</p>
    /// This field is required.
    pub fn quantity(mut self, input: i32) -> Self {
        self.quantity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of HTTP status codes for which you want to specify a custom error page and/or a caching duration. If <code>Quantity</code> is <code>0</code>, you can omit <code>Items</code>.</p>
    pub fn set_quantity(mut self, input: ::std::option::Option<i32>) -> Self {
        self.quantity = input;
        self
    }
    /// <p>The number of HTTP status codes for which you want to specify a custom error page and/or a caching duration. If <code>Quantity</code> is <code>0</code>, you can omit <code>Items</code>.</p>
    pub fn get_quantity(&self) -> &::std::option::Option<i32> {
        &self.quantity
    }
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>A complex type that contains a <code>CustomErrorResponse</code> element for each HTTP status code for which you want to specify a custom error page and/or a caching duration.</p>
    pub fn items(mut self, input: crate::types::CustomErrorResponse) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>A complex type that contains a <code>CustomErrorResponse</code> element for each HTTP status code for which you want to specify a custom error page and/or a caching duration.</p>
    pub fn set_items(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CustomErrorResponse>>) -> Self {
        self.items = input;
        self
    }
    /// <p>A complex type that contains a <code>CustomErrorResponse</code> element for each HTTP status code for which you want to specify a custom error page and/or a caching duration.</p>
    pub fn get_items(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CustomErrorResponse>> {
        &self.items
    }
    /// Consumes the builder and constructs a [`CustomErrorResponses`](crate::types::CustomErrorResponses).
    /// This method will fail if any of the following fields are not set:
    /// - [`quantity`](crate::types::builders::CustomErrorResponsesBuilder::quantity)
    pub fn build(self) -> ::std::result::Result<crate::types::CustomErrorResponses, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CustomErrorResponses {
            quantity: self.quantity.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "quantity",
                    "quantity was not specified but it is required when building CustomErrorResponses",
                )
            })?,
            items: self.items,
        })
    }
}
