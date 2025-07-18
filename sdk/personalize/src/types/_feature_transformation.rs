// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides feature transformation information. Feature transformation is the process of modifying raw input data into a form more suitable for model training.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FeatureTransformation {
    /// <p>The name of the feature transformation.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the FeatureTransformation object.</p>
    pub feature_transformation_arn: ::std::option::Option<::std::string::String>,
    /// <p>Provides the default parameters for feature transformation.</p>
    pub default_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The creation date and time (in Unix time) of the feature transformation.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The last update date and time (in Unix time) of the feature transformation.</p>
    pub last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the feature transformation.</p>
    /// <p>A feature transformation can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// </ul>
    pub status: ::std::option::Option<::std::string::String>,
}
impl FeatureTransformation {
    /// <p>The name of the feature transformation.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the FeatureTransformation object.</p>
    pub fn feature_transformation_arn(&self) -> ::std::option::Option<&str> {
        self.feature_transformation_arn.as_deref()
    }
    /// <p>Provides the default parameters for feature transformation.</p>
    pub fn default_parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.default_parameters.as_ref()
    }
    /// <p>The creation date and time (in Unix time) of the feature transformation.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
    /// <p>The last update date and time (in Unix time) of the feature transformation.</p>
    pub fn last_updated_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_date_time.as_ref()
    }
    /// <p>The status of the feature transformation.</p>
    /// <p>A feature transformation can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
}
impl FeatureTransformation {
    /// Creates a new builder-style object to manufacture [`FeatureTransformation`](crate::types::FeatureTransformation).
    pub fn builder() -> crate::types::builders::FeatureTransformationBuilder {
        crate::types::builders::FeatureTransformationBuilder::default()
    }
}

/// A builder for [`FeatureTransformation`](crate::types::FeatureTransformation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FeatureTransformationBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) feature_transformation_arn: ::std::option::Option<::std::string::String>,
    pub(crate) default_parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
}
impl FeatureTransformationBuilder {
    /// <p>The name of the feature transformation.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the feature transformation.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the feature transformation.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the FeatureTransformation object.</p>
    pub fn feature_transformation_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.feature_transformation_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the FeatureTransformation object.</p>
    pub fn set_feature_transformation_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.feature_transformation_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the FeatureTransformation object.</p>
    pub fn get_feature_transformation_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.feature_transformation_arn
    }
    /// Adds a key-value pair to `default_parameters`.
    ///
    /// To override the contents of this collection use [`set_default_parameters`](Self::set_default_parameters).
    ///
    /// <p>Provides the default parameters for feature transformation.</p>
    pub fn default_parameters(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.default_parameters.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.default_parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Provides the default parameters for feature transformation.</p>
    pub fn set_default_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.default_parameters = input;
        self
    }
    /// <p>Provides the default parameters for feature transformation.</p>
    pub fn get_default_parameters(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.default_parameters
    }
    /// <p>The creation date and time (in Unix time) of the feature transformation.</p>
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The creation date and time (in Unix time) of the feature transformation.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The creation date and time (in Unix time) of the feature transformation.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    /// <p>The last update date and time (in Unix time) of the feature transformation.</p>
    pub fn last_updated_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last update date and time (in Unix time) of the feature transformation.</p>
    pub fn set_last_updated_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_date_time = input;
        self
    }
    /// <p>The last update date and time (in Unix time) of the feature transformation.</p>
    pub fn get_last_updated_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_date_time
    }
    /// <p>The status of the feature transformation.</p>
    /// <p>A feature transformation can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// </ul>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the feature transformation.</p>
    /// <p>A feature transformation can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the feature transformation.</p>
    /// <p>A feature transformation can be in one of the following states:</p>
    /// <ul>
    /// <li>
    /// <p>CREATE PENDING &gt; CREATE IN_PROGRESS &gt; ACTIVE -or- CREATE FAILED</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// Consumes the builder and constructs a [`FeatureTransformation`](crate::types::FeatureTransformation).
    pub fn build(self) -> crate::types::FeatureTransformation {
        crate::types::FeatureTransformation {
            name: self.name,
            feature_transformation_arn: self.feature_transformation_arn,
            default_parameters: self.default_parameters,
            creation_date_time: self.creation_date_time,
            last_updated_date_time: self.last_updated_date_time,
            status: self.status,
        }
    }
}
