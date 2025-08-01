// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteForecastInput {
    /// <p>The Amazon Resource Name (ARN) of the forecast to delete.</p>
    pub forecast_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteForecastInput {
    /// <p>The Amazon Resource Name (ARN) of the forecast to delete.</p>
    pub fn forecast_arn(&self) -> ::std::option::Option<&str> {
        self.forecast_arn.as_deref()
    }
}
impl DeleteForecastInput {
    /// Creates a new builder-style object to manufacture [`DeleteForecastInput`](crate::operation::delete_forecast::DeleteForecastInput).
    pub fn builder() -> crate::operation::delete_forecast::builders::DeleteForecastInputBuilder {
        crate::operation::delete_forecast::builders::DeleteForecastInputBuilder::default()
    }
}

/// A builder for [`DeleteForecastInput`](crate::operation::delete_forecast::DeleteForecastInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteForecastInputBuilder {
    pub(crate) forecast_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteForecastInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the forecast to delete.</p>
    /// This field is required.
    pub fn forecast_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.forecast_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the forecast to delete.</p>
    pub fn set_forecast_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.forecast_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the forecast to delete.</p>
    pub fn get_forecast_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.forecast_arn
    }
    /// Consumes the builder and constructs a [`DeleteForecastInput`](crate::operation::delete_forecast::DeleteForecastInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_forecast::DeleteForecastInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_forecast::DeleteForecastInput {
            forecast_arn: self.forecast_arn,
        })
    }
}
