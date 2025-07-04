// Basic usage example for Cryptonium
const { 
  hashPassword, 
  verifyPassword, 
  sha256, 
  generateSecureSalt,
  assessPasswordStrength,
  generateSecurePassword 
} = require('../lib/index');

async function demonstrateBasicUsage() {
  console.log('🔐 Cryptonium Basic Usage Demo\n');

  // 1. Basic password hashing
  console.log('1. Basic Password Hashing:');
  const password = 'mySecurePassword123!';
  const hashedPassword = hashPassword(password);
  console.log('Original:', password);
  console.log('Hashed:', hashedPassword);
  console.log('');

  // 2. Password verification
  console.log('2. Password Verification:');
  const isValid = verifyPassword(password, hashedPassword);
  const isInvalid = verifyPassword('wrongPassword', hashedPassword);
  console.log('Correct password:', isValid);
  console.log('Wrong password:', isInvalid);
  console.log('');

  // 3. SHA-256 hashing
  console.log('3. SHA-256 Hashing:');
  const message = 'Hello, World!';
  const hash = sha256(message);
  console.log('Message:', message);
  console.log('SHA-256:', hash);
  console.log('');

  // 4. Salt generation
  console.log('4. Salt Generation:');
  const salt = generateSecureSalt(32);
  console.log('Generated salt:', salt);
  console.log('');

  // 5. Password strength assessment
  console.log('5. Password Strength Assessment:');
  const weakPassword = '123456';
  const strongPassword = 'MyStr0ng!P@ssw0rd#2024';
  
  const weakAssessment = assessPasswordStrength(weakPassword);
  const strongAssessment = assessPasswordStrength(strongPassword);
  
  console.log(`Weak password "${weakPassword}":`);
  console.log('- Score:', weakAssessment.score);
  console.log('- Level:', weakAssessment.level);
  console.log('- Feedback:', weakAssessment.feedback.join(', '));
  
  console.log(`Strong password "${strongPassword}":`);
  console.log('- Score:', strongAssessment.score);
  console.log('- Level:', strongAssessment.level);
  console.log('- Feedback:', strongAssessment.feedback.length ? strongAssessment.feedback.join(', ') : 'No issues');
  console.log('');

  // 6. Secure password generation
  console.log('6. Secure Password Generation:');
  const generatedPassword = generateSecurePassword(16, true);
  console.log('Generated password:', generatedPassword);
  const generatedAssessment = assessPasswordStrength(generatedPassword);
  console.log('Generated password strength:', generatedAssessment.level);
  console.log('');

  // 7. Advanced hashing with options
  console.log('7. Advanced Hashing with Options:');
  const advancedHash = hashPassword(password, {
    algorithm: 'sha256',
    saltLength: 32,
    iterations: 50000,
    keyLength: 64
  });
  console.log('Advanced hash:', advancedHash);
  const advancedVerification = verifyPassword(password, advancedHash);
  console.log('Advanced verification:', advancedVerification);
  
  console.log('\n✅ Demo completed successfully!');
}

// Run the demo
demonstrateBasicUsage().catch(console.error); 