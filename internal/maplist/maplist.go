package maplist

import "math/rand"

type MapList[K comparable, V any] struct {
	Data map[K][]V
}

func New[K comparable, V any]() *MapList[K, V] {
	return &MapList[K, V]{
		Data: map[K][]V{},
	}
}

func (m *MapList[K, V]) Add(key K, value V) {
	_, ok := m.Data[key]
	if !ok {
		m.Data[key] = []V{}
	}
	m.Data[key] = []V{value}
}

func (m *MapList[K, V]) GetRandom(key K) V {
	vl := m.Data[key]
	vll := len(vl)
	randIdx := rand.Intn(vll)
	return vl[randIdx]
}
