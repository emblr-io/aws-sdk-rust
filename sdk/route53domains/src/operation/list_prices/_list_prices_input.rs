// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPricesInput {
    /// <p>The TLD for which you want to receive the pricing information. For example. <code>.net</code>.</p>
    /// <p>If a <code>Tld</code> value is not provided, a list of prices for all TLDs supported by Route&nbsp;53 is returned.</p>
    pub tld: ::std::option::Option<::std::string::String>,
    /// <p>For an initial request for a list of prices, omit this element. If the number of prices that are not yet complete is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional prices. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>Marker</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    /// <p>Number of <code>Prices</code> to be returned.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>MaxItems</code>.</p>
    pub max_items: ::std::option::Option<i32>,
}
impl ListPricesInput {
    /// <p>The TLD for which you want to receive the pricing information. For example. <code>.net</code>.</p>
    /// <p>If a <code>Tld</code> value is not provided, a list of prices for all TLDs supported by Route&nbsp;53 is returned.</p>
    pub fn tld(&self) -> ::std::option::Option<&str> {
        self.tld.as_deref()
    }
    /// <p>For an initial request for a list of prices, omit this element. If the number of prices that are not yet complete is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional prices. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>Marker</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
    /// <p>Number of <code>Prices</code> to be returned.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>MaxItems</code>.</p>
    pub fn max_items(&self) -> ::std::option::Option<i32> {
        self.max_items
    }
}
impl ListPricesInput {
    /// Creates a new builder-style object to manufacture [`ListPricesInput`](crate::operation::list_prices::ListPricesInput).
    pub fn builder() -> crate::operation::list_prices::builders::ListPricesInputBuilder {
        crate::operation::list_prices::builders::ListPricesInputBuilder::default()
    }
}

/// A builder for [`ListPricesInput`](crate::operation::list_prices::ListPricesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPricesInputBuilder {
    pub(crate) tld: ::std::option::Option<::std::string::String>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    pub(crate) max_items: ::std::option::Option<i32>,
}
impl ListPricesInputBuilder {
    /// <p>The TLD for which you want to receive the pricing information. For example. <code>.net</code>.</p>
    /// <p>If a <code>Tld</code> value is not provided, a list of prices for all TLDs supported by Route&nbsp;53 is returned.</p>
    pub fn tld(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tld = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The TLD for which you want to receive the pricing information. For example. <code>.net</code>.</p>
    /// <p>If a <code>Tld</code> value is not provided, a list of prices for all TLDs supported by Route&nbsp;53 is returned.</p>
    pub fn set_tld(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tld = input;
        self
    }
    /// <p>The TLD for which you want to receive the pricing information. For example. <code>.net</code>.</p>
    /// <p>If a <code>Tld</code> value is not provided, a list of prices for all TLDs supported by Route&nbsp;53 is returned.</p>
    pub fn get_tld(&self) -> &::std::option::Option<::std::string::String> {
        &self.tld
    }
    /// <p>For an initial request for a list of prices, omit this element. If the number of prices that are not yet complete is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional prices. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>Marker</code>.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For an initial request for a list of prices, omit this element. If the number of prices that are not yet complete is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional prices. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>Marker</code>.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>For an initial request for a list of prices, omit this element. If the number of prices that are not yet complete is greater than the value that you specified for <code>MaxItems</code>, you can use <code>Marker</code> to return additional prices. Get the value of <code>NextPageMarker</code> from the previous response, and submit another request that includes the value of <code>NextPageMarker</code> in the <code>Marker</code> element.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>Marker</code>.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// <p>Number of <code>Prices</code> to be returned.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>MaxItems</code>.</p>
    pub fn max_items(mut self, input: i32) -> Self {
        self.max_items = ::std::option::Option::Some(input);
        self
    }
    /// <p>Number of <code>Prices</code> to be returned.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>MaxItems</code>.</p>
    pub fn set_max_items(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_items = input;
        self
    }
    /// <p>Number of <code>Prices</code> to be returned.</p>
    /// <p>Used only for all TLDs. If you specify a TLD, don't specify a <code>MaxItems</code>.</p>
    pub fn get_max_items(&self) -> &::std::option::Option<i32> {
        &self.max_items
    }
    /// Consumes the builder and constructs a [`ListPricesInput`](crate::operation::list_prices::ListPricesInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_prices::ListPricesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_prices::ListPricesInput {
            tld: self.tld,
            marker: self.marker,
            max_items: self.max_items,
        })
    }
}
