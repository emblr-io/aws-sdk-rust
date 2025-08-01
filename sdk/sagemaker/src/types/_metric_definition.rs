// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a metric that the training algorithm writes to <code>stderr</code> or <code>stdout</code>. You can view these logs to understand how your training job performs and check for any errors encountered during training. SageMaker hyperparameter tuning captures all defined metrics. Specify one of the defined metrics to use as an objective metric using the <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_HyperParameterTrainingJobDefinition.html#sagemaker-Type-HyperParameterTrainingJobDefinition-TuningObjective">TuningObjective</a> parameter in the <code>HyperParameterTrainingJobDefinition</code> API to evaluate job performance during hyperparameter tuning.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetricDefinition {
    /// <p>The name of the metric.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A regular expression that searches the output of a training job and gets the value of the metric. For more information about using regular expressions to define metrics, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-metrics-variables.html">Defining metrics and environment variables</a>.</p>
    pub regex: ::std::option::Option<::std::string::String>,
}
impl MetricDefinition {
    /// <p>The name of the metric.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A regular expression that searches the output of a training job and gets the value of the metric. For more information about using regular expressions to define metrics, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-metrics-variables.html">Defining metrics and environment variables</a>.</p>
    pub fn regex(&self) -> ::std::option::Option<&str> {
        self.regex.as_deref()
    }
}
impl MetricDefinition {
    /// Creates a new builder-style object to manufacture [`MetricDefinition`](crate::types::MetricDefinition).
    pub fn builder() -> crate::types::builders::MetricDefinitionBuilder {
        crate::types::builders::MetricDefinitionBuilder::default()
    }
}

/// A builder for [`MetricDefinition`](crate::types::MetricDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetricDefinitionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) regex: ::std::option::Option<::std::string::String>,
}
impl MetricDefinitionBuilder {
    /// <p>The name of the metric.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the metric.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the metric.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A regular expression that searches the output of a training job and gets the value of the metric. For more information about using regular expressions to define metrics, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-metrics-variables.html">Defining metrics and environment variables</a>.</p>
    /// This field is required.
    pub fn regex(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.regex = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A regular expression that searches the output of a training job and gets the value of the metric. For more information about using regular expressions to define metrics, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-metrics-variables.html">Defining metrics and environment variables</a>.</p>
    pub fn set_regex(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.regex = input;
        self
    }
    /// <p>A regular expression that searches the output of a training job and gets the value of the metric. For more information about using regular expressions to define metrics, see <a href="https://docs.aws.amazon.com/sagemaker/latest/dg/automatic-model-tuning-define-metrics-variables.html">Defining metrics and environment variables</a>.</p>
    pub fn get_regex(&self) -> &::std::option::Option<::std::string::String> {
        &self.regex
    }
    /// Consumes the builder and constructs a [`MetricDefinition`](crate::types::MetricDefinition).
    pub fn build(self) -> crate::types::MetricDefinition {
        crate::types::MetricDefinition {
            name: self.name,
            regex: self.regex,
        }
    }
}
