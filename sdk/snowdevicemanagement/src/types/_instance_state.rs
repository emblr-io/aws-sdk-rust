// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The description of the current state of an instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstanceState {
    /// <p>The state of the instance as a 16-bit unsigned integer.</p>
    /// <p>The high byte is all of the bits between 2^8 and (2^16)-1, which equals decimal values between 256 and 65,535. These numerical values are used for internal purposes and should be ignored.</p>
    /// <p>The low byte is all of the bits between 2^0 and (2^8)-1, which equals decimal values between 0 and 255.</p>
    /// <p>The valid values for the instance state code are all in the range of the low byte. These values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>0</code> : <code>pending</code></p></li>
    /// <li>
    /// <p><code>16</code> : <code>running</code></p></li>
    /// <li>
    /// <p><code>32</code> : <code>shutting-down</code></p></li>
    /// <li>
    /// <p><code>48</code> : <code>terminated</code></p></li>
    /// <li>
    /// <p><code>64</code> : <code>stopping</code></p></li>
    /// <li>
    /// <p><code>80</code> : <code>stopped</code></p></li>
    /// </ul>
    /// <p>You can ignore the high byte value by zeroing out all of the bits above 2^8 or 256 in decimal.</p>
    pub code: ::std::option::Option<i32>,
    /// <p>The current state of the instance.</p>
    pub name: ::std::option::Option<crate::types::InstanceStateName>,
}
impl InstanceState {
    /// <p>The state of the instance as a 16-bit unsigned integer.</p>
    /// <p>The high byte is all of the bits between 2^8 and (2^16)-1, which equals decimal values between 256 and 65,535. These numerical values are used for internal purposes and should be ignored.</p>
    /// <p>The low byte is all of the bits between 2^0 and (2^8)-1, which equals decimal values between 0 and 255.</p>
    /// <p>The valid values for the instance state code are all in the range of the low byte. These values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>0</code> : <code>pending</code></p></li>
    /// <li>
    /// <p><code>16</code> : <code>running</code></p></li>
    /// <li>
    /// <p><code>32</code> : <code>shutting-down</code></p></li>
    /// <li>
    /// <p><code>48</code> : <code>terminated</code></p></li>
    /// <li>
    /// <p><code>64</code> : <code>stopping</code></p></li>
    /// <li>
    /// <p><code>80</code> : <code>stopped</code></p></li>
    /// </ul>
    /// <p>You can ignore the high byte value by zeroing out all of the bits above 2^8 or 256 in decimal.</p>
    pub fn code(&self) -> ::std::option::Option<i32> {
        self.code
    }
    /// <p>The current state of the instance.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::InstanceStateName> {
        self.name.as_ref()
    }
}
impl InstanceState {
    /// Creates a new builder-style object to manufacture [`InstanceState`](crate::types::InstanceState).
    pub fn builder() -> crate::types::builders::InstanceStateBuilder {
        crate::types::builders::InstanceStateBuilder::default()
    }
}

/// A builder for [`InstanceState`](crate::types::InstanceState).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstanceStateBuilder {
    pub(crate) code: ::std::option::Option<i32>,
    pub(crate) name: ::std::option::Option<crate::types::InstanceStateName>,
}
impl InstanceStateBuilder {
    /// <p>The state of the instance as a 16-bit unsigned integer.</p>
    /// <p>The high byte is all of the bits between 2^8 and (2^16)-1, which equals decimal values between 256 and 65,535. These numerical values are used for internal purposes and should be ignored.</p>
    /// <p>The low byte is all of the bits between 2^0 and (2^8)-1, which equals decimal values between 0 and 255.</p>
    /// <p>The valid values for the instance state code are all in the range of the low byte. These values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>0</code> : <code>pending</code></p></li>
    /// <li>
    /// <p><code>16</code> : <code>running</code></p></li>
    /// <li>
    /// <p><code>32</code> : <code>shutting-down</code></p></li>
    /// <li>
    /// <p><code>48</code> : <code>terminated</code></p></li>
    /// <li>
    /// <p><code>64</code> : <code>stopping</code></p></li>
    /// <li>
    /// <p><code>80</code> : <code>stopped</code></p></li>
    /// </ul>
    /// <p>You can ignore the high byte value by zeroing out all of the bits above 2^8 or 256 in decimal.</p>
    pub fn code(mut self, input: i32) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the instance as a 16-bit unsigned integer.</p>
    /// <p>The high byte is all of the bits between 2^8 and (2^16)-1, which equals decimal values between 256 and 65,535. These numerical values are used for internal purposes and should be ignored.</p>
    /// <p>The low byte is all of the bits between 2^0 and (2^8)-1, which equals decimal values between 0 and 255.</p>
    /// <p>The valid values for the instance state code are all in the range of the low byte. These values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>0</code> : <code>pending</code></p></li>
    /// <li>
    /// <p><code>16</code> : <code>running</code></p></li>
    /// <li>
    /// <p><code>32</code> : <code>shutting-down</code></p></li>
    /// <li>
    /// <p><code>48</code> : <code>terminated</code></p></li>
    /// <li>
    /// <p><code>64</code> : <code>stopping</code></p></li>
    /// <li>
    /// <p><code>80</code> : <code>stopped</code></p></li>
    /// </ul>
    /// <p>You can ignore the high byte value by zeroing out all of the bits above 2^8 or 256 in decimal.</p>
    pub fn set_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.code = input;
        self
    }
    /// <p>The state of the instance as a 16-bit unsigned integer.</p>
    /// <p>The high byte is all of the bits between 2^8 and (2^16)-1, which equals decimal values between 256 and 65,535. These numerical values are used for internal purposes and should be ignored.</p>
    /// <p>The low byte is all of the bits between 2^0 and (2^8)-1, which equals decimal values between 0 and 255.</p>
    /// <p>The valid values for the instance state code are all in the range of the low byte. These values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>0</code> : <code>pending</code></p></li>
    /// <li>
    /// <p><code>16</code> : <code>running</code></p></li>
    /// <li>
    /// <p><code>32</code> : <code>shutting-down</code></p></li>
    /// <li>
    /// <p><code>48</code> : <code>terminated</code></p></li>
    /// <li>
    /// <p><code>64</code> : <code>stopping</code></p></li>
    /// <li>
    /// <p><code>80</code> : <code>stopped</code></p></li>
    /// </ul>
    /// <p>You can ignore the high byte value by zeroing out all of the bits above 2^8 or 256 in decimal.</p>
    pub fn get_code(&self) -> &::std::option::Option<i32> {
        &self.code
    }
    /// <p>The current state of the instance.</p>
    pub fn name(mut self, input: crate::types::InstanceStateName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of the instance.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::InstanceStateName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The current state of the instance.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::InstanceStateName> {
        &self.name
    }
    /// Consumes the builder and constructs a [`InstanceState`](crate::types::InstanceState).
    pub fn build(self) -> crate::types::InstanceState {
        crate::types::InstanceState {
            code: self.code,
            name: self.name,
        }
    }
}
