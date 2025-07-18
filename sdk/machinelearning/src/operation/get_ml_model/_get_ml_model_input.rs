// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMlModelInput {
    /// <p>The ID assigned to the <code>MLModel</code> at creation.</p>
    pub ml_model_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether the <code>GetMLModel</code> operation should return <code>Recipe</code>.</p>
    /// <p>If true, <code>Recipe</code> is returned.</p>
    /// <p>If false, <code>Recipe</code> is not returned.</p>
    pub verbose: ::std::option::Option<bool>,
}
impl GetMlModelInput {
    /// <p>The ID assigned to the <code>MLModel</code> at creation.</p>
    pub fn ml_model_id(&self) -> ::std::option::Option<&str> {
        self.ml_model_id.as_deref()
    }
    /// <p>Specifies whether the <code>GetMLModel</code> operation should return <code>Recipe</code>.</p>
    /// <p>If true, <code>Recipe</code> is returned.</p>
    /// <p>If false, <code>Recipe</code> is not returned.</p>
    pub fn verbose(&self) -> ::std::option::Option<bool> {
        self.verbose
    }
}
impl GetMlModelInput {
    /// Creates a new builder-style object to manufacture [`GetMlModelInput`](crate::operation::get_ml_model::GetMlModelInput).
    pub fn builder() -> crate::operation::get_ml_model::builders::GetMlModelInputBuilder {
        crate::operation::get_ml_model::builders::GetMlModelInputBuilder::default()
    }
}

/// A builder for [`GetMlModelInput`](crate::operation::get_ml_model::GetMlModelInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMlModelInputBuilder {
    pub(crate) ml_model_id: ::std::option::Option<::std::string::String>,
    pub(crate) verbose: ::std::option::Option<bool>,
}
impl GetMlModelInputBuilder {
    /// <p>The ID assigned to the <code>MLModel</code> at creation.</p>
    /// This field is required.
    pub fn ml_model_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ml_model_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID assigned to the <code>MLModel</code> at creation.</p>
    pub fn set_ml_model_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ml_model_id = input;
        self
    }
    /// <p>The ID assigned to the <code>MLModel</code> at creation.</p>
    pub fn get_ml_model_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ml_model_id
    }
    /// <p>Specifies whether the <code>GetMLModel</code> operation should return <code>Recipe</code>.</p>
    /// <p>If true, <code>Recipe</code> is returned.</p>
    /// <p>If false, <code>Recipe</code> is not returned.</p>
    pub fn verbose(mut self, input: bool) -> Self {
        self.verbose = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the <code>GetMLModel</code> operation should return <code>Recipe</code>.</p>
    /// <p>If true, <code>Recipe</code> is returned.</p>
    /// <p>If false, <code>Recipe</code> is not returned.</p>
    pub fn set_verbose(mut self, input: ::std::option::Option<bool>) -> Self {
        self.verbose = input;
        self
    }
    /// <p>Specifies whether the <code>GetMLModel</code> operation should return <code>Recipe</code>.</p>
    /// <p>If true, <code>Recipe</code> is returned.</p>
    /// <p>If false, <code>Recipe</code> is not returned.</p>
    pub fn get_verbose(&self) -> &::std::option::Option<bool> {
        &self.verbose
    }
    /// Consumes the builder and constructs a [`GetMlModelInput`](crate::operation::get_ml_model::GetMlModelInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_ml_model::GetMlModelInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_ml_model::GetMlModelInput {
            ml_model_id: self.ml_model_id,
            verbose: self.verbose,
        })
    }
}
