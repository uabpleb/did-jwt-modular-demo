export function buildPidCredentialSubject() {
  return {
    given_name: 'Foo',
    family_name: 'Bar',
    birthdate: '1964-08-12',
    age_over_18: true,
    birth_family_name: 'Baz',
    place_of_birth: { locality: 'Madrid', country: 'ES' },
    nationalities: ['ES', 'AR'],
    address: { street_address: 'Calle Goya', locality: 'Madrid', postal_code: '28009', country: 'ES' },
    sex: 2,
  }
}