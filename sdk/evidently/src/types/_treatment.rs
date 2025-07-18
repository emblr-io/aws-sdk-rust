// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that defines one treatment in an experiment. A treatment is a variation of the feature that you are including in the experiment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Treatment {
    /// <p>The name of this treatment.</p>
    pub name: ::std::string::String,
    /// <p>The description of the treatment.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The feature variation used for this treatment. This is a key-value pair. The key is the feature name, and the value is the variation name.</p>
    pub feature_variations: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl Treatment {
    /// <p>The name of this treatment.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The description of the treatment.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The feature variation used for this treatment. This is a key-value pair. The key is the feature name, and the value is the variation name.</p>
    pub fn feature_variations(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.feature_variations.as_ref()
    }
}
impl Treatment {
    /// Creates a new builder-style object to manufacture [`Treatment`](crate::types::Treatment).
    pub fn builder() -> crate::types::builders::TreatmentBuilder {
        crate::types::builders::TreatmentBuilder::default()
    }
}

/// A builder for [`Treatment`](crate::types::Treatment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TreatmentBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) feature_variations: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl TreatmentBuilder {
    /// <p>The name of this treatment.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of this treatment.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of this treatment.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The description of the treatment.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the treatment.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the treatment.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Adds a key-value pair to `feature_variations`.
    ///
    /// To override the contents of this collection use [`set_feature_variations`](Self::set_feature_variations).
    ///
    /// <p>The feature variation used for this treatment. This is a key-value pair. The key is the feature name, and the value is the variation name.</p>
    pub fn feature_variations(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.feature_variations.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.feature_variations = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The feature variation used for this treatment. This is a key-value pair. The key is the feature name, and the value is the variation name.</p>
    pub fn set_feature_variations(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.feature_variations = input;
        self
    }
    /// <p>The feature variation used for this treatment. This is a key-value pair. The key is the feature name, and the value is the variation name.</p>
    pub fn get_feature_variations(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.feature_variations
    }
    /// Consumes the builder and constructs a [`Treatment`](crate::types::Treatment).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::TreatmentBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::Treatment, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Treatment {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building Treatment",
                )
            })?,
            description: self.description,
            feature_variations: self.feature_variations,
        })
    }
}
