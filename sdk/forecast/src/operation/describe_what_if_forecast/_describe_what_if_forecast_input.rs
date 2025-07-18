// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeWhatIfForecastInput {
    /// <p>The Amazon Resource Name (ARN) of the what-if forecast that you are interested in.</p>
    pub what_if_forecast_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeWhatIfForecastInput {
    /// <p>The Amazon Resource Name (ARN) of the what-if forecast that you are interested in.</p>
    pub fn what_if_forecast_arn(&self) -> ::std::option::Option<&str> {
        self.what_if_forecast_arn.as_deref()
    }
}
impl DescribeWhatIfForecastInput {
    /// Creates a new builder-style object to manufacture [`DescribeWhatIfForecastInput`](crate::operation::describe_what_if_forecast::DescribeWhatIfForecastInput).
    pub fn builder() -> crate::operation::describe_what_if_forecast::builders::DescribeWhatIfForecastInputBuilder {
        crate::operation::describe_what_if_forecast::builders::DescribeWhatIfForecastInputBuilder::default()
    }
}

/// A builder for [`DescribeWhatIfForecastInput`](crate::operation::describe_what_if_forecast::DescribeWhatIfForecastInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeWhatIfForecastInputBuilder {
    pub(crate) what_if_forecast_arn: ::std::option::Option<::std::string::String>,
}
impl DescribeWhatIfForecastInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the what-if forecast that you are interested in.</p>
    /// This field is required.
    pub fn what_if_forecast_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.what_if_forecast_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the what-if forecast that you are interested in.</p>
    pub fn set_what_if_forecast_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.what_if_forecast_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the what-if forecast that you are interested in.</p>
    pub fn get_what_if_forecast_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.what_if_forecast_arn
    }
    /// Consumes the builder and constructs a [`DescribeWhatIfForecastInput`](crate::operation::describe_what_if_forecast::DescribeWhatIfForecastInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_what_if_forecast::DescribeWhatIfForecastInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_what_if_forecast::DescribeWhatIfForecastInput {
            what_if_forecast_arn: self.what_if_forecast_arn,
        })
    }
}
