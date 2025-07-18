// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A job flow step consisting of a JAR file whose main function will be executed. The main function submits a job for Hadoop to execute and waits for the job to finish or fail.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HadoopJarStepConfig {
    /// <p>A list of Java properties that are set when the step runs. You can use these properties to pass key-value pairs to your main function.</p>
    pub properties: ::std::option::Option<::std::vec::Vec<crate::types::KeyValue>>,
    /// <p>A path to a JAR file run during the step.</p>
    pub jar: ::std::option::Option<::std::string::String>,
    /// <p>The name of the main class in the specified Java file. If not specified, the JAR file should specify a Main-Class in its manifest file.</p>
    pub main_class: ::std::option::Option<::std::string::String>,
    /// <p>A list of command line arguments passed to the JAR file's main function when executed.</p>
    pub args: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl HadoopJarStepConfig {
    /// <p>A list of Java properties that are set when the step runs. You can use these properties to pass key-value pairs to your main function.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.properties.is_none()`.
    pub fn properties(&self) -> &[crate::types::KeyValue] {
        self.properties.as_deref().unwrap_or_default()
    }
    /// <p>A path to a JAR file run during the step.</p>
    pub fn jar(&self) -> ::std::option::Option<&str> {
        self.jar.as_deref()
    }
    /// <p>The name of the main class in the specified Java file. If not specified, the JAR file should specify a Main-Class in its manifest file.</p>
    pub fn main_class(&self) -> ::std::option::Option<&str> {
        self.main_class.as_deref()
    }
    /// <p>A list of command line arguments passed to the JAR file's main function when executed.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.args.is_none()`.
    pub fn args(&self) -> &[::std::string::String] {
        self.args.as_deref().unwrap_or_default()
    }
}
impl HadoopJarStepConfig {
    /// Creates a new builder-style object to manufacture [`HadoopJarStepConfig`](crate::types::HadoopJarStepConfig).
    pub fn builder() -> crate::types::builders::HadoopJarStepConfigBuilder {
        crate::types::builders::HadoopJarStepConfigBuilder::default()
    }
}

/// A builder for [`HadoopJarStepConfig`](crate::types::HadoopJarStepConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HadoopJarStepConfigBuilder {
    pub(crate) properties: ::std::option::Option<::std::vec::Vec<crate::types::KeyValue>>,
    pub(crate) jar: ::std::option::Option<::std::string::String>,
    pub(crate) main_class: ::std::option::Option<::std::string::String>,
    pub(crate) args: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl HadoopJarStepConfigBuilder {
    /// Appends an item to `properties`.
    ///
    /// To override the contents of this collection use [`set_properties`](Self::set_properties).
    ///
    /// <p>A list of Java properties that are set when the step runs. You can use these properties to pass key-value pairs to your main function.</p>
    pub fn properties(mut self, input: crate::types::KeyValue) -> Self {
        let mut v = self.properties.unwrap_or_default();
        v.push(input);
        self.properties = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of Java properties that are set when the step runs. You can use these properties to pass key-value pairs to your main function.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::KeyValue>>) -> Self {
        self.properties = input;
        self
    }
    /// <p>A list of Java properties that are set when the step runs. You can use these properties to pass key-value pairs to your main function.</p>
    pub fn get_properties(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::KeyValue>> {
        &self.properties
    }
    /// <p>A path to a JAR file run during the step.</p>
    /// This field is required.
    pub fn jar(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.jar = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A path to a JAR file run during the step.</p>
    pub fn set_jar(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.jar = input;
        self
    }
    /// <p>A path to a JAR file run during the step.</p>
    pub fn get_jar(&self) -> &::std::option::Option<::std::string::String> {
        &self.jar
    }
    /// <p>The name of the main class in the specified Java file. If not specified, the JAR file should specify a Main-Class in its manifest file.</p>
    pub fn main_class(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.main_class = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the main class in the specified Java file. If not specified, the JAR file should specify a Main-Class in its manifest file.</p>
    pub fn set_main_class(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.main_class = input;
        self
    }
    /// <p>The name of the main class in the specified Java file. If not specified, the JAR file should specify a Main-Class in its manifest file.</p>
    pub fn get_main_class(&self) -> &::std::option::Option<::std::string::String> {
        &self.main_class
    }
    /// Appends an item to `args`.
    ///
    /// To override the contents of this collection use [`set_args`](Self::set_args).
    ///
    /// <p>A list of command line arguments passed to the JAR file's main function when executed.</p>
    pub fn args(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.args.unwrap_or_default();
        v.push(input.into());
        self.args = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of command line arguments passed to the JAR file's main function when executed.</p>
    pub fn set_args(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.args = input;
        self
    }
    /// <p>A list of command line arguments passed to the JAR file's main function when executed.</p>
    pub fn get_args(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.args
    }
    /// Consumes the builder and constructs a [`HadoopJarStepConfig`](crate::types::HadoopJarStepConfig).
    pub fn build(self) -> crate::types::HadoopJarStepConfig {
        crate::types::HadoopJarStepConfig {
            properties: self.properties,
            jar: self.jar,
            main_class: self.main_class,
            args: self.args,
        }
    }
}
