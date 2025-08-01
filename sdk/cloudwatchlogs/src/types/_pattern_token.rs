// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that contains information about one pattern token related to an anomaly.</p>
/// <p>For more information about patterns and tokens, see <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_CreateLogAnomalyDetector.html">CreateLogAnomalyDetector</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PatternToken {
    /// <p>For a dynamic token, this indicates where in the pattern that this token appears, related to other dynamic tokens. The dynamic token that appears first has a value of <code>1</code>, the one that appears second is <code>2</code>, and so on.</p>
    pub dynamic_token_position: i32,
    /// <p>Specifies whether this is a dynamic token.</p>
    pub is_dynamic: ::std::option::Option<bool>,
    /// <p>The string represented by this token. If this is a dynamic token, the value will be <code>&lt;*&gt;</code></p>
    pub token_string: ::std::option::Option<::std::string::String>,
    /// <p>Contains the values found for a dynamic token, and the number of times each value was found.</p>
    pub enumerations: ::std::option::Option<::std::collections::HashMap<::std::string::String, i64>>,
    /// <p>A name that CloudWatch Logs assigned to this dynamic token to make the pattern more readable. The string part of the <code>inferredTokenName</code> gives you a clearer idea of the content of this token. The number part of the <code>inferredTokenName</code> shows where in the pattern this token appears, compared to other dynamic tokens. CloudWatch Logs assigns the string part of the name based on analyzing the content of the log events that contain it.</p>
    /// <p>For example, an inferred token name of <code>IPAddress-3</code> means that the token represents an IP address, and this token is the third dynamic token in the pattern.</p>
    pub inferred_token_name: ::std::option::Option<::std::string::String>,
}
impl PatternToken {
    /// <p>For a dynamic token, this indicates where in the pattern that this token appears, related to other dynamic tokens. The dynamic token that appears first has a value of <code>1</code>, the one that appears second is <code>2</code>, and so on.</p>
    pub fn dynamic_token_position(&self) -> i32 {
        self.dynamic_token_position
    }
    /// <p>Specifies whether this is a dynamic token.</p>
    pub fn is_dynamic(&self) -> ::std::option::Option<bool> {
        self.is_dynamic
    }
    /// <p>The string represented by this token. If this is a dynamic token, the value will be <code>&lt;*&gt;</code></p>
    pub fn token_string(&self) -> ::std::option::Option<&str> {
        self.token_string.as_deref()
    }
    /// <p>Contains the values found for a dynamic token, and the number of times each value was found.</p>
    pub fn enumerations(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, i64>> {
        self.enumerations.as_ref()
    }
    /// <p>A name that CloudWatch Logs assigned to this dynamic token to make the pattern more readable. The string part of the <code>inferredTokenName</code> gives you a clearer idea of the content of this token. The number part of the <code>inferredTokenName</code> shows where in the pattern this token appears, compared to other dynamic tokens. CloudWatch Logs assigns the string part of the name based on analyzing the content of the log events that contain it.</p>
    /// <p>For example, an inferred token name of <code>IPAddress-3</code> means that the token represents an IP address, and this token is the third dynamic token in the pattern.</p>
    pub fn inferred_token_name(&self) -> ::std::option::Option<&str> {
        self.inferred_token_name.as_deref()
    }
}
impl PatternToken {
    /// Creates a new builder-style object to manufacture [`PatternToken`](crate::types::PatternToken).
    pub fn builder() -> crate::types::builders::PatternTokenBuilder {
        crate::types::builders::PatternTokenBuilder::default()
    }
}

/// A builder for [`PatternToken`](crate::types::PatternToken).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PatternTokenBuilder {
    pub(crate) dynamic_token_position: ::std::option::Option<i32>,
    pub(crate) is_dynamic: ::std::option::Option<bool>,
    pub(crate) token_string: ::std::option::Option<::std::string::String>,
    pub(crate) enumerations: ::std::option::Option<::std::collections::HashMap<::std::string::String, i64>>,
    pub(crate) inferred_token_name: ::std::option::Option<::std::string::String>,
}
impl PatternTokenBuilder {
    /// <p>For a dynamic token, this indicates where in the pattern that this token appears, related to other dynamic tokens. The dynamic token that appears first has a value of <code>1</code>, the one that appears second is <code>2</code>, and so on.</p>
    pub fn dynamic_token_position(mut self, input: i32) -> Self {
        self.dynamic_token_position = ::std::option::Option::Some(input);
        self
    }
    /// <p>For a dynamic token, this indicates where in the pattern that this token appears, related to other dynamic tokens. The dynamic token that appears first has a value of <code>1</code>, the one that appears second is <code>2</code>, and so on.</p>
    pub fn set_dynamic_token_position(mut self, input: ::std::option::Option<i32>) -> Self {
        self.dynamic_token_position = input;
        self
    }
    /// <p>For a dynamic token, this indicates where in the pattern that this token appears, related to other dynamic tokens. The dynamic token that appears first has a value of <code>1</code>, the one that appears second is <code>2</code>, and so on.</p>
    pub fn get_dynamic_token_position(&self) -> &::std::option::Option<i32> {
        &self.dynamic_token_position
    }
    /// <p>Specifies whether this is a dynamic token.</p>
    pub fn is_dynamic(mut self, input: bool) -> Self {
        self.is_dynamic = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether this is a dynamic token.</p>
    pub fn set_is_dynamic(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_dynamic = input;
        self
    }
    /// <p>Specifies whether this is a dynamic token.</p>
    pub fn get_is_dynamic(&self) -> &::std::option::Option<bool> {
        &self.is_dynamic
    }
    /// <p>The string represented by this token. If this is a dynamic token, the value will be <code>&lt;*&gt;</code></p>
    pub fn token_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The string represented by this token. If this is a dynamic token, the value will be <code>&lt;*&gt;</code></p>
    pub fn set_token_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token_string = input;
        self
    }
    /// <p>The string represented by this token. If this is a dynamic token, the value will be <code>&lt;*&gt;</code></p>
    pub fn get_token_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.token_string
    }
    /// Adds a key-value pair to `enumerations`.
    ///
    /// To override the contents of this collection use [`set_enumerations`](Self::set_enumerations).
    ///
    /// <p>Contains the values found for a dynamic token, and the number of times each value was found.</p>
    pub fn enumerations(mut self, k: impl ::std::convert::Into<::std::string::String>, v: i64) -> Self {
        let mut hash_map = self.enumerations.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.enumerations = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Contains the values found for a dynamic token, and the number of times each value was found.</p>
    pub fn set_enumerations(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, i64>>) -> Self {
        self.enumerations = input;
        self
    }
    /// <p>Contains the values found for a dynamic token, and the number of times each value was found.</p>
    pub fn get_enumerations(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, i64>> {
        &self.enumerations
    }
    /// <p>A name that CloudWatch Logs assigned to this dynamic token to make the pattern more readable. The string part of the <code>inferredTokenName</code> gives you a clearer idea of the content of this token. The number part of the <code>inferredTokenName</code> shows where in the pattern this token appears, compared to other dynamic tokens. CloudWatch Logs assigns the string part of the name based on analyzing the content of the log events that contain it.</p>
    /// <p>For example, an inferred token name of <code>IPAddress-3</code> means that the token represents an IP address, and this token is the third dynamic token in the pattern.</p>
    pub fn inferred_token_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.inferred_token_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name that CloudWatch Logs assigned to this dynamic token to make the pattern more readable. The string part of the <code>inferredTokenName</code> gives you a clearer idea of the content of this token. The number part of the <code>inferredTokenName</code> shows where in the pattern this token appears, compared to other dynamic tokens. CloudWatch Logs assigns the string part of the name based on analyzing the content of the log events that contain it.</p>
    /// <p>For example, an inferred token name of <code>IPAddress-3</code> means that the token represents an IP address, and this token is the third dynamic token in the pattern.</p>
    pub fn set_inferred_token_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.inferred_token_name = input;
        self
    }
    /// <p>A name that CloudWatch Logs assigned to this dynamic token to make the pattern more readable. The string part of the <code>inferredTokenName</code> gives you a clearer idea of the content of this token. The number part of the <code>inferredTokenName</code> shows where in the pattern this token appears, compared to other dynamic tokens. CloudWatch Logs assigns the string part of the name based on analyzing the content of the log events that contain it.</p>
    /// <p>For example, an inferred token name of <code>IPAddress-3</code> means that the token represents an IP address, and this token is the third dynamic token in the pattern.</p>
    pub fn get_inferred_token_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.inferred_token_name
    }
    /// Consumes the builder and constructs a [`PatternToken`](crate::types::PatternToken).
    pub fn build(self) -> crate::types::PatternToken {
        crate::types::PatternToken {
            dynamic_token_position: self.dynamic_token_position.unwrap_or_default(),
            is_dynamic: self.is_dynamic,
            token_string: self.token_string,
            enumerations: self.enumerations,
            inferred_token_name: self.inferred_token_name,
        }
    }
}
