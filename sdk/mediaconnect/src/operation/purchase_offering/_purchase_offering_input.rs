// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PurchaseOfferingInput {
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    pub offering_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name that you want to use for the reservation.</p>
    pub reservation_name: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that you want the reservation to begin, in Coordinated Universal Time (UTC).</p>
    /// <p>You can specify any date and time between 12:00am on the first day of the current month to the current time on today's date, inclusive. Specify the start in a 24-hour notation. Use the following format: <code>YYYY-MM-DDTHH:mm:SSZ</code>, where <code>T</code> and <code>Z</code> are literal characters. For example, to specify 11:30pm on March 5, 2020, enter <code>2020-03-05T23:30:00Z</code>.</p>
    pub start: ::std::option::Option<::std::string::String>,
}
impl PurchaseOfferingInput {
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    pub fn offering_arn(&self) -> ::std::option::Option<&str> {
        self.offering_arn.as_deref()
    }
    /// <p>The name that you want to use for the reservation.</p>
    pub fn reservation_name(&self) -> ::std::option::Option<&str> {
        self.reservation_name.as_deref()
    }
    /// <p>The date and time that you want the reservation to begin, in Coordinated Universal Time (UTC).</p>
    /// <p>You can specify any date and time between 12:00am on the first day of the current month to the current time on today's date, inclusive. Specify the start in a 24-hour notation. Use the following format: <code>YYYY-MM-DDTHH:mm:SSZ</code>, where <code>T</code> and <code>Z</code> are literal characters. For example, to specify 11:30pm on March 5, 2020, enter <code>2020-03-05T23:30:00Z</code>.</p>
    pub fn start(&self) -> ::std::option::Option<&str> {
        self.start.as_deref()
    }
}
impl PurchaseOfferingInput {
    /// Creates a new builder-style object to manufacture [`PurchaseOfferingInput`](crate::operation::purchase_offering::PurchaseOfferingInput).
    pub fn builder() -> crate::operation::purchase_offering::builders::PurchaseOfferingInputBuilder {
        crate::operation::purchase_offering::builders::PurchaseOfferingInputBuilder::default()
    }
}

/// A builder for [`PurchaseOfferingInput`](crate::operation::purchase_offering::PurchaseOfferingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PurchaseOfferingInputBuilder {
    pub(crate) offering_arn: ::std::option::Option<::std::string::String>,
    pub(crate) reservation_name: ::std::option::Option<::std::string::String>,
    pub(crate) start: ::std::option::Option<::std::string::String>,
}
impl PurchaseOfferingInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    /// This field is required.
    pub fn offering_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.offering_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    pub fn set_offering_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.offering_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the offering.</p>
    pub fn get_offering_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.offering_arn
    }
    /// <p>The name that you want to use for the reservation.</p>
    /// This field is required.
    pub fn reservation_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reservation_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name that you want to use for the reservation.</p>
    pub fn set_reservation_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reservation_name = input;
        self
    }
    /// <p>The name that you want to use for the reservation.</p>
    pub fn get_reservation_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.reservation_name
    }
    /// <p>The date and time that you want the reservation to begin, in Coordinated Universal Time (UTC).</p>
    /// <p>You can specify any date and time between 12:00am on the first day of the current month to the current time on today's date, inclusive. Specify the start in a 24-hour notation. Use the following format: <code>YYYY-MM-DDTHH:mm:SSZ</code>, where <code>T</code> and <code>Z</code> are literal characters. For example, to specify 11:30pm on March 5, 2020, enter <code>2020-03-05T23:30:00Z</code>.</p>
    /// This field is required.
    pub fn start(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time that you want the reservation to begin, in Coordinated Universal Time (UTC).</p>
    /// <p>You can specify any date and time between 12:00am on the first day of the current month to the current time on today's date, inclusive. Specify the start in a 24-hour notation. Use the following format: <code>YYYY-MM-DDTHH:mm:SSZ</code>, where <code>T</code> and <code>Z</code> are literal characters. For example, to specify 11:30pm on March 5, 2020, enter <code>2020-03-05T23:30:00Z</code>.</p>
    pub fn set_start(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start = input;
        self
    }
    /// <p>The date and time that you want the reservation to begin, in Coordinated Universal Time (UTC).</p>
    /// <p>You can specify any date and time between 12:00am on the first day of the current month to the current time on today's date, inclusive. Specify the start in a 24-hour notation. Use the following format: <code>YYYY-MM-DDTHH:mm:SSZ</code>, where <code>T</code> and <code>Z</code> are literal characters. For example, to specify 11:30pm on March 5, 2020, enter <code>2020-03-05T23:30:00Z</code>.</p>
    pub fn get_start(&self) -> &::std::option::Option<::std::string::String> {
        &self.start
    }
    /// Consumes the builder and constructs a [`PurchaseOfferingInput`](crate::operation::purchase_offering::PurchaseOfferingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::purchase_offering::PurchaseOfferingInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::purchase_offering::PurchaseOfferingInput {
            offering_arn: self.offering_arn,
            reservation_name: self.reservation_name,
            start: self.start,
        })
    }
}
