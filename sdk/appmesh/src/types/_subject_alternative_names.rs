// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the subject alternative names secured by the certificate.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SubjectAlternativeNames {
    /// <p>An object that represents the criteria for determining a SANs match.</p>
    pub r#match: ::std::option::Option<crate::types::SubjectAlternativeNameMatchers>,
}
impl SubjectAlternativeNames {
    /// <p>An object that represents the criteria for determining a SANs match.</p>
    pub fn r#match(&self) -> ::std::option::Option<&crate::types::SubjectAlternativeNameMatchers> {
        self.r#match.as_ref()
    }
}
impl SubjectAlternativeNames {
    /// Creates a new builder-style object to manufacture [`SubjectAlternativeNames`](crate::types::SubjectAlternativeNames).
    pub fn builder() -> crate::types::builders::SubjectAlternativeNamesBuilder {
        crate::types::builders::SubjectAlternativeNamesBuilder::default()
    }
}

/// A builder for [`SubjectAlternativeNames`](crate::types::SubjectAlternativeNames).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SubjectAlternativeNamesBuilder {
    pub(crate) r#match: ::std::option::Option<crate::types::SubjectAlternativeNameMatchers>,
}
impl SubjectAlternativeNamesBuilder {
    /// <p>An object that represents the criteria for determining a SANs match.</p>
    /// This field is required.
    pub fn r#match(mut self, input: crate::types::SubjectAlternativeNameMatchers) -> Self {
        self.r#match = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that represents the criteria for determining a SANs match.</p>
    pub fn set_match(mut self, input: ::std::option::Option<crate::types::SubjectAlternativeNameMatchers>) -> Self {
        self.r#match = input;
        self
    }
    /// <p>An object that represents the criteria for determining a SANs match.</p>
    pub fn get_match(&self) -> &::std::option::Option<crate::types::SubjectAlternativeNameMatchers> {
        &self.r#match
    }
    /// Consumes the builder and constructs a [`SubjectAlternativeNames`](crate::types::SubjectAlternativeNames).
    pub fn build(self) -> crate::types::SubjectAlternativeNames {
        crate::types::SubjectAlternativeNames { r#match: self.r#match }
    }
}
