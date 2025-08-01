// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of continuous hyperparameters to tune.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContinuousParameterRange {
    /// <p>The name of the continuous hyperparameter to tune.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The minimum value for the hyperparameter. The tuning job uses floating-point values between this value and <code>MaxValue</code>for tuning.</p>
    pub min_value: ::std::option::Option<::std::string::String>,
    /// <p>The maximum value for the hyperparameter. The tuning job uses floating-point values between <code>MinValue</code> value and this value for tuning.</p>
    pub max_value: ::std::option::Option<::std::string::String>,
    /// <p>The scale that hyperparameter tuning uses to search the hyperparameter range. For information about choosing a hyperparameter scale, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-ranges.html#scaling-type">Hyperparameter Scaling</a>. One of the following values:</p>
    /// <dl>
    /// <dt>
    /// Auto
    /// </dt>
    /// <dd>
    /// <p>SageMaker hyperparameter tuning chooses the best scale for the hyperparameter.</p>
    /// </dd>
    /// <dt>
    /// Linear
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a linear scale.</p>
    /// </dd>
    /// <dt>
    /// Logarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a logarithmic scale.</p>
    /// <p>Logarithmic scaling works only for ranges that have only values greater than 0.</p>
    /// </dd>
    /// <dt>
    /// ReverseLogarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a reverse logarithmic scale.</p>
    /// <p>Reverse logarithmic scaling works only for ranges that are entirely within the range 0&lt;=x&lt;1.0.</p>
    /// </dd>
    /// </dl>
    pub scaling_type: ::std::option::Option<crate::types::HyperParameterScalingType>,
}
impl ContinuousParameterRange {
    /// <p>The name of the continuous hyperparameter to tune.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The minimum value for the hyperparameter. The tuning job uses floating-point values between this value and <code>MaxValue</code>for tuning.</p>
    pub fn min_value(&self) -> ::std::option::Option<&str> {
        self.min_value.as_deref()
    }
    /// <p>The maximum value for the hyperparameter. The tuning job uses floating-point values between <code>MinValue</code> value and this value for tuning.</p>
    pub fn max_value(&self) -> ::std::option::Option<&str> {
        self.max_value.as_deref()
    }
    /// <p>The scale that hyperparameter tuning uses to search the hyperparameter range. For information about choosing a hyperparameter scale, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-ranges.html#scaling-type">Hyperparameter Scaling</a>. One of the following values:</p>
    /// <dl>
    /// <dt>
    /// Auto
    /// </dt>
    /// <dd>
    /// <p>SageMaker hyperparameter tuning chooses the best scale for the hyperparameter.</p>
    /// </dd>
    /// <dt>
    /// Linear
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a linear scale.</p>
    /// </dd>
    /// <dt>
    /// Logarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a logarithmic scale.</p>
    /// <p>Logarithmic scaling works only for ranges that have only values greater than 0.</p>
    /// </dd>
    /// <dt>
    /// ReverseLogarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a reverse logarithmic scale.</p>
    /// <p>Reverse logarithmic scaling works only for ranges that are entirely within the range 0&lt;=x&lt;1.0.</p>
    /// </dd>
    /// </dl>
    pub fn scaling_type(&self) -> ::std::option::Option<&crate::types::HyperParameterScalingType> {
        self.scaling_type.as_ref()
    }
}
impl ContinuousParameterRange {
    /// Creates a new builder-style object to manufacture [`ContinuousParameterRange`](crate::types::ContinuousParameterRange).
    pub fn builder() -> crate::types::builders::ContinuousParameterRangeBuilder {
        crate::types::builders::ContinuousParameterRangeBuilder::default()
    }
}

/// A builder for [`ContinuousParameterRange`](crate::types::ContinuousParameterRange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContinuousParameterRangeBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) min_value: ::std::option::Option<::std::string::String>,
    pub(crate) max_value: ::std::option::Option<::std::string::String>,
    pub(crate) scaling_type: ::std::option::Option<crate::types::HyperParameterScalingType>,
}
impl ContinuousParameterRangeBuilder {
    /// <p>The name of the continuous hyperparameter to tune.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the continuous hyperparameter to tune.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the continuous hyperparameter to tune.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The minimum value for the hyperparameter. The tuning job uses floating-point values between this value and <code>MaxValue</code>for tuning.</p>
    /// This field is required.
    pub fn min_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.min_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The minimum value for the hyperparameter. The tuning job uses floating-point values between this value and <code>MaxValue</code>for tuning.</p>
    pub fn set_min_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.min_value = input;
        self
    }
    /// <p>The minimum value for the hyperparameter. The tuning job uses floating-point values between this value and <code>MaxValue</code>for tuning.</p>
    pub fn get_min_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.min_value
    }
    /// <p>The maximum value for the hyperparameter. The tuning job uses floating-point values between <code>MinValue</code> value and this value for tuning.</p>
    /// This field is required.
    pub fn max_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.max_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The maximum value for the hyperparameter. The tuning job uses floating-point values between <code>MinValue</code> value and this value for tuning.</p>
    pub fn set_max_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.max_value = input;
        self
    }
    /// <p>The maximum value for the hyperparameter. The tuning job uses floating-point values between <code>MinValue</code> value and this value for tuning.</p>
    pub fn get_max_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.max_value
    }
    /// <p>The scale that hyperparameter tuning uses to search the hyperparameter range. For information about choosing a hyperparameter scale, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-ranges.html#scaling-type">Hyperparameter Scaling</a>. One of the following values:</p>
    /// <dl>
    /// <dt>
    /// Auto
    /// </dt>
    /// <dd>
    /// <p>SageMaker hyperparameter tuning chooses the best scale for the hyperparameter.</p>
    /// </dd>
    /// <dt>
    /// Linear
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a linear scale.</p>
    /// </dd>
    /// <dt>
    /// Logarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a logarithmic scale.</p>
    /// <p>Logarithmic scaling works only for ranges that have only values greater than 0.</p>
    /// </dd>
    /// <dt>
    /// ReverseLogarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a reverse logarithmic scale.</p>
    /// <p>Reverse logarithmic scaling works only for ranges that are entirely within the range 0&lt;=x&lt;1.0.</p>
    /// </dd>
    /// </dl>
    pub fn scaling_type(mut self, input: crate::types::HyperParameterScalingType) -> Self {
        self.scaling_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The scale that hyperparameter tuning uses to search the hyperparameter range. For information about choosing a hyperparameter scale, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-ranges.html#scaling-type">Hyperparameter Scaling</a>. One of the following values:</p>
    /// <dl>
    /// <dt>
    /// Auto
    /// </dt>
    /// <dd>
    /// <p>SageMaker hyperparameter tuning chooses the best scale for the hyperparameter.</p>
    /// </dd>
    /// <dt>
    /// Linear
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a linear scale.</p>
    /// </dd>
    /// <dt>
    /// Logarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a logarithmic scale.</p>
    /// <p>Logarithmic scaling works only for ranges that have only values greater than 0.</p>
    /// </dd>
    /// <dt>
    /// ReverseLogarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a reverse logarithmic scale.</p>
    /// <p>Reverse logarithmic scaling works only for ranges that are entirely within the range 0&lt;=x&lt;1.0.</p>
    /// </dd>
    /// </dl>
    pub fn set_scaling_type(mut self, input: ::std::option::Option<crate::types::HyperParameterScalingType>) -> Self {
        self.scaling_type = input;
        self
    }
    /// <p>The scale that hyperparameter tuning uses to search the hyperparameter range. For information about choosing a hyperparameter scale, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-ranges.html#scaling-type">Hyperparameter Scaling</a>. One of the following values:</p>
    /// <dl>
    /// <dt>
    /// Auto
    /// </dt>
    /// <dd>
    /// <p>SageMaker hyperparameter tuning chooses the best scale for the hyperparameter.</p>
    /// </dd>
    /// <dt>
    /// Linear
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a linear scale.</p>
    /// </dd>
    /// <dt>
    /// Logarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a logarithmic scale.</p>
    /// <p>Logarithmic scaling works only for ranges that have only values greater than 0.</p>
    /// </dd>
    /// <dt>
    /// ReverseLogarithmic
    /// </dt>
    /// <dd>
    /// <p>Hyperparameter tuning searches the values in the hyperparameter range by using a reverse logarithmic scale.</p>
    /// <p>Reverse logarithmic scaling works only for ranges that are entirely within the range 0&lt;=x&lt;1.0.</p>
    /// </dd>
    /// </dl>
    pub fn get_scaling_type(&self) -> &::std::option::Option<crate::types::HyperParameterScalingType> {
        &self.scaling_type
    }
    /// Consumes the builder and constructs a [`ContinuousParameterRange`](crate::types::ContinuousParameterRange).
    pub fn build(self) -> crate::types::ContinuousParameterRange {
        crate::types::ContinuousParameterRange {
            name: self.name,
            min_value: self.min_value,
            max_value: self.max_value,
            scaling_type: self.scaling_type,
        }
    }
}
